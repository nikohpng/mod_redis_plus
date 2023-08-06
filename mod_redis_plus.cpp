#include "mod_redis_plus.h"

SWITCH_MODULE_LOAD_FUNCTION(mod_redis_plus_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_redis_plus_shutdown);
SWITCH_MODULE_DEFINITION(mod_redis_plus, mod_redis_plus_load, mod_redis_plus_shutdown, NULL);

/**
 * Get exclusive access to limit_pvt, if it exists
 */
static redis_plus_limit_pvt_t *get_limit_pvt(switch_core_session_t *session)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);

    redis_plus_limit_pvt_t *limit_pvt = (redis_plus_limit_pvt_t*)switch_channel_get_private(channel, "hiredis_limit_pvt");
    if (limit_pvt) {
        /* pvt already exists, return it */
        switch_mutex_lock(limit_pvt->mutex);
        return limit_pvt;
    }
    return NULL;
}

/**
 * Add limit_pvt and get exclusive access to it
 */
static redis_plus_limit_pvt_t *add_limit_pvt(switch_core_session_t *session)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);

    redis_plus_limit_pvt_t *limit_pvt = (redis_plus_limit_pvt_t*)switch_channel_get_private(channel, "hiredis_limit_pvt");
    if (limit_pvt) {
        /* pvt already exists, return it */
        switch_mutex_lock(limit_pvt->mutex);
        return limit_pvt;
    }

    /* not created yet, add it - NOTE a channel mutex would be better here if we had access to it */
    switch_mutex_lock(mod_redis_plus_globals.limit_pvt_mutex);
    limit_pvt = (redis_plus_limit_pvt_t*)switch_channel_get_private(channel, "hiredis_limit_pvt");
    if (limit_pvt) {
        /* was just added by another thread */
        switch_mutex_unlock(mod_redis_plus_globals.limit_pvt_mutex);
        switch_mutex_lock(limit_pvt->mutex);
        return limit_pvt;
    }

    /* still not created yet, add it */
    limit_pvt = (redis_plus_limit_pvt_t*)switch_core_session_alloc(session, sizeof(*limit_pvt));
    switch_mutex_init(&limit_pvt->mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
    limit_pvt->first = NULL;
    switch_channel_set_private(channel, "hiredis_limit_pvt", (void*)limit_pvt);
    switch_mutex_unlock(mod_redis_plus_globals.limit_pvt_mutex);
    switch_mutex_lock(limit_pvt->mutex);
    return limit_pvt;
}

/**
 * Release exclusive acess to limit_pvt
 */
static void release_limit_pvt(redis_plus_limit_pvt_t *limit_pvt)
{
    if (limit_pvt) {
        switch_mutex_unlock(limit_pvt->mutex);
    }
}

SWITCH_STANDARD_APP(raw_app)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
    char *response = NULL, *profile_name = NULL, *cmd = NULL;
    redis_plus_profile_t *profile = NULL;

    if ( !zstr(data) ) {
        profile_name = strdup(data);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: invalid data! Use the format 'default set keyname value' \n");
        goto done;
    }

    if ( (cmd = strchr(profile_name, ' '))) {
        *cmd = '\0';
        cmd++;
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: invalid data! Use the format 'default set keyname value' \n");
        goto done;
    }

    profile = (redis_plus_profile_t*)switch_core_hash_find(mod_redis_plus_globals.profiles, profile_name);

    if ( !profile ) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: Unable to locate profile[%s]\n", profile_name);
        return;
    }

    if ( redis_plus_profile_execute(profile, session, &response, cmd) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: profile[%s] error executing [%s] because [%s]\n", profile_name, cmd, response ? response : "");
    }

    switch_channel_set_variable(channel, "hiredis_raw_response", response ? response : "");

    done:
    switch_safe_free(profile_name);
    switch_safe_free(response);
    return;
}

SWITCH_STANDARD_API(raw_api)
{
    redis_plus_profile_t *profile = NULL;
    char *data = NULL, *input = NULL, *response = NULL;
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if ( !zstr(cmd) ) {
        input = strdup(cmd);
    } else {
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if ( (data = strchr(input, ' '))) {
        *data = '\0';
        data++;
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "hiredis: debug: profile[%s] for command [%s]\n", input, data);

    profile = (redis_plus_profile_t*)switch_core_hash_find(mod_redis_plus_globals.profiles, input);

    if ( !profile ) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: Unable to locate profile[%s]\n", input);
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if ( redis_plus_profile_execute(profile, session, &response, data) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: profile[%s] error executing [%s] reason:[%s]\n", input, data, response ? response : "");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if (response) {
        stream->write_function(stream, response);
    }
    done:
    switch_safe_free(input);
    switch_safe_free(response);
    return status;
}

/*
SWITCH_LIMIT_INCR(name) static switch_status_t name (switch_core_session_t *session, const char *realm, const char *resource,
                                                     const int max, const int interval)
*/
SWITCH_LIMIT_INCR(redis_plus_limit_incr)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
    redis_plus_profile_t *profile = NULL;
    char *response = NULL, *limit_key = NULL;
    int64_t count = 0; /* Redis defines the incr action as to be performed on a 64 bit signed integer */
    time_t now = switch_epoch_time_now(NULL);
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    redis_plus_limit_pvt_t *limit_pvt = NULL;
    redis_plus_limit_pvt_node_t *limit_pvt_node = NULL;
    switch_memory_pool_t *session_pool = switch_core_session_get_pool(session);

    if ( zstr(realm) ) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: realm must be defined\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if ( interval < 0 ) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: interval must be >= 0\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    profile = (redis_plus_profile_t*)switch_core_hash_find(mod_redis_plus_globals.profiles, realm);

    if ( !profile ) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: Unable to locate profile[%s]\n", realm);
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if ( interval ) {
        limit_key = switch_core_session_sprintf(session, "%s_%d", resource, now / interval);
    } else {
        limit_key = switch_core_session_sprintf(session, "%s", resource);
    }

    if ( (status = redis_plus_profile_execute_pipeline_printf(profile, session, &response, "incr %s", limit_key) ) != SWITCH_STATUS_SUCCESS ) {
        if ( status == SWITCH_STATUS_SOCKERR && profile->ignore_connect_fail) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "hiredis: ignoring profile[%s] connection error incrementing [%s]\n", realm, limit_key);
            switch_goto_status(SWITCH_STATUS_SUCCESS, done);
        } else if ( profile->ignore_error ) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "hiredis: ignoring profile[%s] general error incrementing [%s]\n", realm, limit_key);
            switch_goto_status(SWITCH_STATUS_SUCCESS, done);
        }
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: profile[%s] error incrementing [%s] because [%s]\n", realm, limit_key, response ? response : "");
        switch_channel_set_variable(channel, "hiredis_raw_response", response ? response : "");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    /* set expiration for interval on first increment */
    if ( interval && !strcmp("1", response ? response : "") ) {
        redis_plus_profile_execute_pipeline_printf(profile, session, NULL, "expire %s %d", limit_key, interval);
    }

    switch_channel_set_variable(channel, "hiredis_raw_response", response ? response : "");

    count = atoll(response ? response : "");

    if ( switch_is_number(response ? response : "") && count <= 0 ) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "limit not positive after increment, resource = %s, val = %s\n", limit_key, response ? response : "");
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "resource = %s, response = %s\n", limit_key, response ? response : "");
    }

    if ( !switch_is_number(response ? response : "") && !profile->ignore_error ) {
        /* got response error */
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    } else if ( max > 0 && count > 0 && count > max ) {
        switch_channel_set_variable(channel, "hiredis_limit_exceeded", "true");
        if ( !interval ) { /* don't need to decrement intervals if limit exceeded since the interval keys are named w/ timestamp */
            redis_plus_profile_execute_pipeline_printf(profile, session, NULL, "decr %s", limit_key);
        }
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if ( !interval && count > 0 ) {
        /* only non-interval limits need to be released on session destroy */
        limit_pvt_node = (redis_plus_limit_pvt_node_t*)switch_core_alloc(session_pool, sizeof(*limit_pvt_node));
        limit_pvt_node->realm = switch_core_strdup(session_pool, realm);
        limit_pvt_node->resource = switch_core_strdup(session_pool, resource);
        limit_pvt_node->limit_key = limit_key;
        limit_pvt_node->inc = 1;
        limit_pvt_node->interval = interval;
        limit_pvt = add_limit_pvt(session);
        limit_pvt_node->next = limit_pvt->first;
        limit_pvt->first = limit_pvt_node;
        release_limit_pvt(limit_pvt);
    }

    done:
    switch_safe_free(response);
    return status;
}

/*
  SWITCH_LIMIT_RELEASE(name) static switch_status_t name (switch_core_session_t *session, const char *realm, const char *resource)
*/
SWITCH_LIMIT_RELEASE(redis_plus_limit_release)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
    redis_plus_profile_t *profile = NULL;
    char *response = NULL;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    redis_plus_limit_pvt_t *limit_pvt = get_limit_pvt(session);

    if (!limit_pvt) {
        /* nothing to release */
        return SWITCH_STATUS_SUCCESS;
    }

    /* If realm and resource are NULL, then clear all of the limits */
    if ( zstr(realm) && zstr(resource) ) {
        redis_plus_limit_pvt_node_t *cur = NULL;

        for ( cur = limit_pvt->first; cur; cur = cur->next ) {
            /* Rate limited resources are not auto-decremented, they will expire. */
            if ( !cur->interval && cur->inc ) {
                switch_status_t result;
                cur->inc = 0; /* mark as released */
                profile = (redis_plus_profile_t*)switch_core_hash_find(mod_redis_plus_globals.profiles, cur->realm);
                result = redis_plus_profile_execute_pipeline_printf(profile, session, &response, "decr %s", cur->limit_key);
                if ( result != SWITCH_STATUS_SUCCESS ) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: profile[%s] error decrementing [%s] because [%s]\n",
                                      cur->realm, cur->limit_key, response ? response : "");
                }
                switch_safe_free(response);
                response = NULL;
            }
        }
    } else if (!zstr(resource) ) {
        /* clear single non-interval resource */
        redis_plus_limit_pvt_node_t *cur = NULL;
        for (cur = limit_pvt->first; cur; cur = cur->next ) {
            if ( !cur->interval && cur->inc && !strcmp(cur->resource, resource) && (zstr(realm) || !strcmp(cur->realm, realm)) ) {
                /* found the resource to clear */
                cur->inc = 0; /* mark as released */
                profile = (redis_plus_profile_t*)switch_core_hash_find(mod_redis_plus_globals.profiles, cur->realm);
                if (profile) {
                    status = redis_plus_profile_execute_pipeline_printf(profile, session, &response, "decr %s", cur->limit_key);
                    if ( status != SWITCH_STATUS_SUCCESS ) {
                        if ( status == SWITCH_STATUS_SOCKERR && profile->ignore_connect_fail ) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "hiredis: ignoring profile[%s] connection error decrementing [%s]\n", cur->realm, cur->limit_key);
                            switch_goto_status(SWITCH_STATUS_SUCCESS, done);
                        } else if ( profile->ignore_error ) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "hiredis: ignoring profile[%s] general error decrementing [%s]\n", realm, cur->limit_key);
                            switch_goto_status(SWITCH_STATUS_SUCCESS, done);
                        }
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "hiredis: profile[%s] error decrementing [%s] because [%s]\n", realm, cur->limit_key, response ? response : "");
                        switch_channel_set_variable(channel, "hiredis_raw_response", response ? response : "");
                        switch_goto_status(SWITCH_STATUS_GENERR, done);
                    }

                    switch_channel_set_variable(channel, "hiredis_raw_response", response ? response : "");
                }
                break;
            }
        }
    }

    done:
    release_limit_pvt(limit_pvt);
    switch_safe_free(response);
    return status;
}

/*
SWITCH_LIMIT_USAGE(name) static int name (const char *realm, const char *resource, uint32_t *rcount)
 */
SWITCH_LIMIT_USAGE(redis_plus_limit_usage)
{
    redis_plus_profile_t *profile = (redis_plus_profile_t*)switch_core_hash_find(mod_redis_plus_globals.profiles, realm);
    int64_t count = 0; /* Redis defines the incr action as to be performed on a 64 bit signed integer */
    char *response = NULL;

    if ( zstr(realm) ) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "hiredis: realm must be defined\n");
        goto err;
    }

    if ( !profile ) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "hiredis: Unable to locate profile[%s]\n", realm);
        goto err;
    }

    if ( redis_plus_profile_execute_pipeline_printf(profile, NULL, &response, "get %s", resource) != SWITCH_STATUS_SUCCESS ) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "hiredis: profile[%s] error querying [%s] because [%s]\n", realm, resource, response ? response : "");
        goto err;
    }

    count = atoll(response ? response : "");

    switch_safe_free(response);
    return count;

    err:
    switch_safe_free(response);
    return -1;
}

/*
SWITCH_LIMIT_RESET(name) static switch_status_t name (void)
 */
SWITCH_LIMIT_RESET(redis_plus_limit_reset)
{
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "hiredis: unable to globally reset hiredis limit resources. Use 'hiredis_raw set resource_name 0'\n");
    return SWITCH_STATUS_NOTIMPL;
}

/*
  SWITCH_LIMIT_INTERVAL_RESET(name) static switch_status_t name (const char *realm, const char *resource)
*/
SWITCH_LIMIT_INTERVAL_RESET(redis_plus_limit_interval_reset)
{
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "hiredis: unable to reset hiredis interval limit resources.\n");
    return SWITCH_STATUS_NOTIMPL;
}

/*
SWITCH_LIMIT_STATUS(name) static char * name (void)
 */
SWITCH_LIMIT_STATUS(redis_plus_limit_status)
{
    return strdup("-ERR not supported");
}

SWITCH_MODULE_LOAD_FUNCTION(mod_redis_plus_load)
{
    switch_application_interface_t *app_interface;
    switch_api_interface_t *api_interface;
    switch_limit_interface_t *limit_interface;

    memset(&mod_redis_plus_globals, 0, sizeof(mod_redis_plus_globals));
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);
    mod_redis_plus_globals.pool = pool;
    switch_mutex_init(&mod_redis_plus_globals.limit_pvt_mutex, SWITCH_MUTEX_NESTED, pool);

    switch_core_hash_init(&(mod_redis_plus_globals.profiles));

    if ( mod_redis_plus_do_config() != SWITCH_STATUS_SUCCESS ) {
        return SWITCH_STATUS_GENERR;
    }

    SWITCH_ADD_LIMIT(limit_interface, "redis_plus", redis_plus_limit_incr, redis_plus_limit_release, redis_plus_limit_usage,
                     redis_plus_limit_reset, redis_plus_limit_status, redis_plus_limit_interval_reset);
    SWITCH_ADD_APP(app_interface, "redis_plus_raw", "redis_plus_raw", "redis_plus_raw", raw_app, "", SAF_SUPPORT_NOMEDIA | SAF_ROUTING_EXEC | SAF_ZOMBIE_EXEC);
    SWITCH_ADD_API(api_interface, "redis_plus_raw", "redis_plus_raw", raw_api, "");

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_redis_plus_shutdown)
{

    switch_hash_index_t *hi;
    redis_plus_profile_t *profile = NULL;
    /* loop through profiles, and destroy them */

    while ((hi = switch_core_hash_first(mod_redis_plus_globals.profiles))) {
        switch_core_hash_this(hi, NULL, NULL, (void **)&profile);
        redis_plus_profile_destroy(&profile);
        switch_safe_free(hi);
    }

    switch_core_hash_destroy(&(mod_redis_plus_globals.profiles));

    return SWITCH_STATUS_SUCCESS;
}
