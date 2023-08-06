#include "mod_redis_plus.h"


switch_status_t mod_redis_plus_do_config()
{
    const char *conf = "redis_plus.conf";
    switch_xml_t xml, cfg, profiles, profile, connections, connection, params, param;

    if (!(xml = switch_xml_open_cfg(conf, &cfg, NULL))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", conf);
        goto err;
    }

    if ( (profiles = switch_xml_child(cfg, "profiles")) != NULL) {
        for (profile = switch_xml_child(profiles, "profile"); profile; profile = profile->next) {
            redis_plus_profile_t *new_profile = NULL;
            uint8_t ignore_connect_fail = 0;
            uint8_t ignore_error = 0;
            char *name = (char *) switch_xml_attr_soft(profile, "name");

            // Load params
            if ( (params = switch_xml_child(profile, "params")) != NULL) {
                for (param = switch_xml_child(params, "param"); param; param = param->next) {
                    char *var = (char *) switch_xml_attr_soft(param, "name");
                    if ( !strncmp(var, "ignore-connect-fail", 19) ) {
                        ignore_connect_fail = switch_true(switch_xml_attr_soft(param, "value"));
                    } else if ( !strncmp(var, "ignore-error", 12) ) {
                        ignore_error = switch_true(switch_xml_attr_soft(param, "value"));
                    }
                }
            }

            if ( redis_plus_profile_create(&new_profile, name, ignore_connect_fail, ignore_error) == SWITCH_STATUS_SUCCESS ) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Created profile[%s]\n", name);
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create profile[%s]\n", name);
            }

            /* Add connection to profile */
            if ( (connection = switch_xml_child(profile, "connection")) != NULL) {
                char *host = NULL, *password = NULL;
                uint32_t port = 0, timeout_ms = 0, max_connections = 0, redis_type = 0, pool_size = 0, sync_flag = 0;

                for (param = switch_xml_child(connection, "param"); param; param = param->next) {
                    char *var = (char *) switch_xml_attr_soft(param, "name");
                    if ( !strncmp(var, "hostname", 8) ) {
                        host = (char *) switch_xml_attr_soft(param, "value");
                    } else if ( !strncmp(var, "port", 4) ) {
                        port = atoi(switch_xml_attr_soft(param, "value"));
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "hiredis: adding conn[%u == %s]\n", port, switch_xml_attr_soft(param, "value"));
                    } else if ( !strncmp(var, "timeout-ms", 10) || !strncmp(var, "timeout_ms", 10) ) {
                        timeout_ms = atoi(switch_xml_attr_soft(param, "value"));
                    } else if ( !strncmp(var, "password", 8) ) {
                        password = (char *) switch_xml_attr_soft(param, "value");
                    } else if ( !strncmp(var, "max-connections", 15) ) {
                        max_connections = atoi(switch_xml_attr_soft(param, "value"));
                    } else if ( !strncmp(var, "redis-type", 10)) {
                        redis_type = atoi(switch_xml_attr_soft(param, "value"));
                    } else if ( !strncmp(var, "pool-size", 9)) {
                        pool_size = atoi(switch_xml_attr_soft(param, "value"));
                    }
                }

                if ( redis_plus_profile_connection_add(new_profile, host, password, port, timeout_ms, max_connections, redis_type, pool_size) == SWITCH_STATUS_SUCCESS) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Created profile[%s]\n", name);
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create profile[%s]\n", name);
                }
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile->connections config is missing\n");
                goto err;
            }
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profiles config is missing\n");
        goto err;
    }

    switch_xml_free(xml);
    return SWITCH_STATUS_SUCCESS;

    err:
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Configuration failed\n");
    if (xml) {
        switch_xml_free(xml);
    }
    return SWITCH_STATUS_GENERR;
}
