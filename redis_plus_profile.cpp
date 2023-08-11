#include "mod_redis_plus.h"

switch_status_t redis_plus_profile_create(redis_plus_profile_t **new_profile, char *name, uint8_t ignore_connect_fail,
                                          uint8_t ignore_error, int max_pipelined_requests) {
    redis_plus_profile_t *profile = NULL;
    switch_memory_pool_t *pool = NULL;

    switch_core_new_memory_pool(&pool);

    profile = (redis_plus_profile_t *) switch_core_alloc(pool, sizeof(redis_plus_profile_t));

    profile->pool = pool;
    profile->name = name ? switch_core_strdup(profile->pool, name) : (char *) "default";
    profile->connection = NULL;
    profile->ignore_connect_fail = ignore_connect_fail;
    profile->ignore_error = ignore_error;

    profile->pipeline_running = 0;
    profile->max_pipelined_requests = max_pipelined_requests;
    switch_thread_rwlock_create(&profile->pipeline_lock, pool);
    switch_queue_create(&profile->active_requests, 2000, pool);

    switch_core_hash_insert(mod_redis_plus_globals.profiles, name, (void *) profile);

    *new_profile = profile;

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t redis_plus_profile_destroy(redis_plus_profile_t **old_profile) {
    redis_plus_profile_t *profile = NULL;

    if (!old_profile || !*old_profile) {
        return SWITCH_STATUS_SUCCESS;
    } else {
        profile = *old_profile;
        *old_profile = NULL;
    }

    redis_plus_pipeline_threads_stop(profile);
    profile->connection->redis_cluster = NULL;
    profile->connection->master_redis = NULL;
    profile->connection->slave_redis = NULL;
    //profile->connection->pipeline = NULL;

    switch_core_hash_delete(mod_redis_plus_globals.profiles, profile->name);
    switch_core_destroy_memory_pool(&(profile->pool));

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
redis_plus_profile_connection_add(redis_plus_profile_t *profile, char *host, char *password, uint32_t port,
                                  uint32_t timeout_ms, uint32_t max_connections, uint32_t redis_type,
                                  uint32_t pool_size, char *master_name, uint32_t sentinel_timeout_ms) {
    redis_plus_connection_t *new_conn = NULL;
    char *input = NULL;
    if (!zstr(host)) {
        input = strdup(host);
    } else {
        return SWITCH_STATUS_GENERR;
    }
    new_conn = (redis_plus_connection_t *) switch_core_alloc(profile->pool, sizeof(redis_plus_connection_t));
    new_conn->host = host ? switch_core_strdup(profile->pool, host) : (char *) "localhost";
    new_conn->password = password ? switch_core_strdup(profile->pool, password) : NULL;
    new_conn->port = port ? port : 6379;
    new_conn->pool = profile->pool;
    new_conn->redis_type = redis_type;
    new_conn->pool_size = pool_size;

    if (timeout_ms) {
        new_conn->timeout_us = timeout_ms * 1000;
        new_conn->timeout.tv_sec = timeout_ms / 1000;
        new_conn->timeout.tv_usec = (timeout_ms % 1000) * 1000;
    } else {
        new_conn->timeout_us = 500 * 1000;
        new_conn->timeout.tv_sec = 0;
        new_conn->timeout.tv_usec = 500 * 1000;
    }

    ConnectionOptions opts;
    if (redis_type != 2) {
        opts.host = new_conn->host;
        opts.port = new_conn->port;
    }
    opts.password = new_conn->password;
    opts.connect_timeout = std::chrono::milliseconds(new_conn->timeout_us);   // Required.
    opts.socket_timeout = std::chrono::milliseconds(new_conn->timeout_us);    // Required.

    ConnectionPoolOptions pool_opts;
    pool_opts.size = 3;

    try {
        if (redis_type == 0) {
            auto redis = new Redis(opts, pool_opts);
            new_conn->master_redis = std::unique_ptr<Redis>(redis);
        } else if (redis_type == 1) {
            auto redis_cluster = new RedisCluster(opts, pool_opts);
            new_conn->redis_cluster = std::unique_ptr<RedisCluster>(redis_cluster);
        } else if (redis_type == 2) {
            // read hosts
            char *sentinel_host = NULL;
            bool flag = true;
            SentinelOptions sentinel_opts;
            while (flag) {
                char *host = input, *port = NULL, *tmp = NULL;
                if ((sentinel_host = strchr(input, ','))) {
                    *sentinel_host = '\0';
                    sentinel_host++;
                } else {
                    flag = false;
                }

                if ((tmp = strchr(input, ':'))) {
                    *tmp = '\0';
                    port = ++tmp;
                    input = sentinel_host;
                    sentinel_opts.nodes.push_back(std::make_pair<std::string, int>(std::string(host), atoi(port)));
                }

            }
        
            if (master_name == nullptr) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "redis_plus: sentinel type need master_name!");
                goto done;
            }

            sentinel_opts.connect_timeout = std::chrono::milliseconds(200);
            sentinel_opts.socket_timeout = std::chrono::milliseconds(200);
            auto sentinel = std::make_shared<Sentinel>(sentinel_opts);
            auto master_redis = new Redis(sentinel, std::string(master_name), Role::MASTER, opts, pool_opts);
            auto slave_redis = new Redis(sentinel, std::string(master_name), Role::SLAVE, opts, pool_opts);
            new_conn->master_redis = std::unique_ptr<Redis>(master_redis);
            new_conn->slave_redis = std::unique_ptr<Redis>(slave_redis);
        }
    }catch(std::exception &e) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "redis_plus can't create connection: %s", e.what());
        goto done;
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "redis_plus: adding conn[%s,%d], pool size = %d\n",
                      new_conn->host, new_conn->port, pool_size);
    profile->connection = new_conn;
    redis_plus_pipeline_thread_start(profile);
    done:
    switch_safe_free(input);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
redis_plus_profile_execute(redis_plus_profile_t *profile, switch_core_session_t *session, char **response,
                           const char *data) {
    redis_plus_connection_t *conn = profile->connection;
    ReplyUPtr resp;
    if (conn) {
        std::vector <std::string> commands = get_commands((char*)data);
        try {
            if (conn->redis_type == 0) {
                resp = conn->master_redis->command(commands.begin(), commands.end());
            } else if (conn->redis_type == 1) {
                resp = conn->redis_cluster->command(commands.begin(), commands.end());
            } else if (conn->redis_type == 2) {
                if (strstr(data, "GET") != nullptr || strstr(data, "EXISTS")
                || strstr(data, "get") != nullptr || strstr(data, "exists")) {
                    resp = conn->slave_redis->command(commands.begin(), commands.end());
                } else {
                    resp = conn->master_redis->command(commands.begin(), commands.end());
                }
            }
            if (reply::is_integer(*resp)) {
                auto int_resp = reply::parse<long long>(*resp);
                *response = switch_mprintf("%lld", int_resp);
            } else if (reply::is_string(*resp)) {
                auto option_resp = reply::parse<OptionalString>(*resp);
                *response = strdup(option_resp.value().c_str());
#ifdef REDIS_PLUS_PLUS_RESP_VERSION_3
            } else if (reply::is_double(*resp)) {
                auto double_resp = reply::parse<double>(*resp);
                *response = switch_mprintf("%f", double_resp);
            } else if (reply::is_bool(*resp)) {
                auto bool_resp = reply::parse<long long>(*resp);
                *response = switch_mprintf("%lld", bool_resp);
#endif
            } else {
                auto option_resp = reply::parse<OptionalString>(*resp);
                *response = strdup(option_resp.value().c_str());
            }
            return SWITCH_STATUS_SUCCESS;
        } catch (const ReplyError &e) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "redis_plus can't get reply: %s", e.what());
        } catch (const std::exception &e) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "redis_plus unkown error: %s", e.what());
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "redis_plus: can't find redis connection\n");
    }
    return SWITCH_STATUS_GENERR;
}
