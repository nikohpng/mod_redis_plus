#include "mod_redis_plus.h"


std::vector<std::string> get_commands(char *data) {
    bool flag = true;
    std::vector<std::string> commands;
    while(flag) {
        char *command = NULL;
        if ((command = strchr(data, ' '))) {
            *command = '\0';
            command++;
        } else {
            flag = false;
        }
        commands.push_back(std::string(data));
        data = command;
    }
    return commands;
}


static void *SWITCH_THREAD_FUNC pipeline_thread(switch_thread_t *thread, void *obj)
{
    redis_plus_profile_t *profile = (redis_plus_profile_t *)obj;
    switch_thread_rwlock_rdlock(profile->pipeline_lock);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Redis pipeline thread started for [%s]\n", profile->name);

    while ( profile->pipeline_running || switch_queue_size(profile->active_requests) > 0 ) {
        void *val = NULL;
        if ( switch_queue_pop_timeout(profile->active_requests, &val, 500 * 1000) == SWITCH_STATUS_SUCCESS && val ) {
            int idx = 0;
            auto conn = profile->connection;
            int request_count = 1;
            std::vector<std::string> responses;
            QueuedReplies replies;
            redis_plus_request_t *requests = (redis_plus_request_t *)val;
            redis_plus_request_t *cur_request = requests;
            cur_request->next = NULL;
            /* This would be easier to code in reverse order, but I prefer to execute requests in the order that they arrive */
            while ( request_count < profile->max_pipelined_requests ) {
                if ( switch_queue_trypop(profile->active_requests, &val) == SWITCH_STATUS_SUCCESS && val ) {
                    request_count++;
                    cur_request = cur_request->next = (redis_plus_request_t *)val;
                    cur_request->next = NULL;
                } else {
                    break;
                }
            }
            if (profile->connection->is_init) {
                if (conn->redis_type == 0) {
                    conn->pipeline = conn->master_redis->pipeline();
                } else if (conn->redis_type == 2) {
                    conn->pipeline = conn->master_redis->pipeline();
                }
                conn->is_init = false;
            }
            // do
            // hiredis_profile_execute_requests(profile, NULL, requests);
            try{
                cur_request = requests;
                while ( cur_request ) {
                    redis_plus_request_t *next_request = cur_request->next;
                    if( cur_request->request) {
                        char *data = cur_request->request;
                        std::vector<std::string> commands = get_commands(data);
                        if (conn->redis_type == 1) {
                            try{
                                auto rs = conn->redis_cluster->command<std::string>(commands.begin(), commands.end());
                                responses.push_back(rs);
                            }catch(ReplyError e) {
                                responses.push_back("");
                            }
                        } else {
                            conn->pipeline.command(commands.begin(), commands.end());
                        }

                    }
                    cur_request = next_request;
                }

                if (conn->redis_type != 1) {
                    try{
                        replies = conn->pipeline.exec();
                    }catch(ReplyError e) {
                        conn->is_init = false;
                        continue;
                    }

                }
            }catch(...) {
                conn->is_init = false;
                continue;
            }

            cur_request = requests;
            while ( cur_request ) {
                redis_plus_request_t *next_request = cur_request->next; /* done here to prevent race with waiter */
                std::string response;
                if (conn->redis_type == 1) {
                    response = responses.at(idx++);
                } else {
                    response = replies.get<std::string>(idx++);
                }
                if (!response.empty()) {
                    *cur_request->response = strdup(response.c_str());
                    /* signal waiter */
                    switch_mutex_lock(cur_request->mutex);
                    cur_request->done = 1;
                    switch_thread_cond_signal(cur_request->cond);
                    switch_mutex_unlock(cur_request->mutex);
                } else {
                    /* nobody to signal, clean it up */
                    switch_safe_free(cur_request->request);
                    switch_safe_free(cur_request->session_uuid);
                    switch_queue_trypush(profile->request_pool, cur_request);
                }
                cur_request = next_request;
            }
        }
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Redis pipeline thread ended for [%s]\n", profile->name);

    switch_thread_rwlock_unlock(profile->pipeline_lock);

    return NULL;
}

void redis_plus_pipeline_thread_start(redis_plus_profile_t *profile)
{
    switch_thread_t *thread;
    switch_threadattr_t *thd_attr = NULL;
    profile->pipeline_running = 1;
    switch_threadattr_create(&thd_attr, profile->pool);
    switch_threadattr_detach_set(thd_attr, 1);
    switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
    switch_thread_create(&thread, thd_attr, pipeline_thread, profile, profile->pool);
}

void redis_plus_pipeline_threads_stop(redis_plus_profile_t *profile)
{
    if ( profile->pipeline_running ) {
        profile->pipeline_running = 0;
        switch_queue_interrupt_all(profile->active_requests);
        switch_thread_rwlock_wrlock(profile->pipeline_lock);
    }
}

static switch_status_t redis_plus_profile_execute_pipeline_request(redis_plus_profile_t *profile, switch_core_session_t *session, redis_plus_request_t *request)
{
    switch_status_t status;

    /* send request to thread pool */
    if ( profile->pipeline_running && switch_queue_trypush(profile->active_requests, request) == SWITCH_STATUS_SUCCESS ) {
        if ( request->response ) {
            /* wait for response */
            switch_mutex_lock(request->mutex);
            while ( !request->done ) {
                switch_thread_cond_timedwait(request->cond, request->mutex, 1000 * 1000);
            }

            /* get response */
            switch_mutex_unlock(request->mutex);
            status = request->status;

            /* save back to pool */
            switch_queue_trypush(profile->request_pool, request);
        } else {
            status = SWITCH_STATUS_SUCCESS;
        }
    } else {
       status = SWITCH_STATUS_FALSE;
    }
    return status;
}

static switch_status_t redis_plus_profile_execute_pipeline(redis_plus_profile_t *profile, switch_core_session_t *session, char **resp, const char *request_string)
{
    void *val = NULL;
    redis_plus_request_t *request = NULL;

    if (switch_queue_trypop(profile->request_pool, &val) == SWITCH_STATUS_SUCCESS && val) {
        request = (redis_plus_request_t *)val;
    } else {
        request = (redis_plus_request_t*)switch_core_alloc(profile->pool, sizeof(*request));
        switch_thread_cond_create(&request->cond, profile->pool);
        switch_mutex_init(&request->mutex, SWITCH_MUTEX_UNNESTED, profile->pool);
    }
    request->response = resp;
    request->done = 0;
    request->status = SWITCH_STATUS_SUCCESS;
    request->next = NULL;
    request->session_uuid = NULL;
    if ( resp ) {
        /* will block, no need to dup memory */
        request->request = (char *)request_string;
        if ( session ) {
            request->session_uuid = switch_core_session_get_uuid(session);
        }
    } else {
        /* fire and forget... need to dup memory */
        request->request = strdup(request_string);
        if ( session ) {
            request->session_uuid = strdup(switch_core_session_get_uuid(session));
        }
    }

    return redis_plus_profile_execute_pipeline_request(profile, session, request);
}

switch_status_t redis_plus_profile_execute_pipeline_printf(redis_plus_profile_t *profile, switch_core_session_t *session, char **resp, const char *format_string, ...)
{
    switch_status_t result = SWITCH_STATUS_GENERR;
    char *request = NULL;
    va_list ap;
    int ret;

    va_start(ap, format_string);
    ret = switch_vasprintf(&request, format_string, ap);
    va_end(ap);

    if ( ret != -1 ) {
        result = redis_plus_profile_execute_pipeline(profile, session, resp, request);
    }
    switch_safe_free(request);
    return result;
}