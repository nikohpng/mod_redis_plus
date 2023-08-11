#include <switch.h>
#include <switch_event.h>
#include <sw/redis++/redis++.h>
#include <stdint-gcc.h>
using namespace sw::redis;

typedef struct mod_redis_plus_global_s {
    switch_memory_pool_t *pool;
    switch_hash_t *profiles;
    switch_mutex_t *limit_pvt_mutex;
} mod_redis_plus_global_t;
extern mod_redis_plus_global_t mod_redis_plus_globals;

typedef struct redis_plus_request_s {
    char *request;
    char **response;
    int done;
    char *session_uuid;
    switch_status_t status;
    switch_mutex_t *mutex;
    switch_thread_cond_t *cond;
    struct redis_plus_request_s *next;
} redis_plus_request_t;

typedef struct redis_plus_connection_s {
    char *host;
    char *password;
    uint32_t port;
    switch_interval_time_t timeout_us;
    struct timeval timeout;
    uint32_t redis_type;
    uint32_t pool_size;
    uint32_t sync;
    switch_memory_pool_t *pool;

    Pipeline pipeline;
    bool is_init;
    std::unique_ptr<RedisCluster> redis_cluster;
    std::unique_ptr<Redis> master_redis;
    std::unique_ptr<Redis> slave_redis;
} redis_plus_connection_t;

typedef struct redis_plus_profile_s {
    switch_memory_pool_t *pool;
    char *name;
    uint8_t ignore_connect_fail;
    uint8_t ignore_error;
    redis_plus_connection_t *connection;

    switch_thread_rwlock_t *pipeline_lock;
    switch_queue_t *request_pool;
    switch_queue_t *active_requests;
    int pipeline_running;
    int max_pipelined_requests;
} redis_plus_profile_t;

typedef struct redis_plus_limit_pvt_node_s {
    char *realm;
    char *resource;
    char *limit_key;
    int inc;
    int interval;
    struct redis_plus_limit_pvt_node_s *next;
} redis_plus_limit_pvt_node_t;

typedef struct redis_plus_limit_pvt_s {
    switch_mutex_t *mutex;
    struct redis_plus_limit_pvt_node_s *first;
} redis_plus_limit_pvt_t;

switch_status_t mod_redis_plus_do_config(void);
std::vector<std::string> get_commands(char *data);
switch_status_t redis_plus_profile_create(redis_plus_profile_t **new_profile, char *name, uint8_t ignore_connect_fail, uint8_t ignore_error, int max_pipelined_requests);
switch_status_t redis_plus_profile_destroy(redis_plus_profile_t **old_profile);
switch_status_t redis_plus_profile_connection_add(redis_plus_profile_t *profile, char *host, char *password, uint32_t port, uint32_t timeout_ms,
                                                  uint32_t max_connections, uint32_t redis_type, uint32_t pool_size);
switch_status_t redis_plus_profile_execute(redis_plus_profile_t *profile, switch_core_session_t *session, char **response, const char *data);

void redis_plus_pipeline_thread_start(redis_plus_profile_t *profile);
void redis_plus_pipeline_threads_stop(redis_plus_profile_t *profile);
switch_status_t redis_plus_profile_execute_pipeline_printf(redis_plus_profile_t *profile, switch_core_session_t *session, char **response, const char *data_format_string, ...);
switch_status_t redis_plus_profile_eval_pipeline(redis_plus_profile_t *profile, switch_core_session_t *session, char **response, const char *script, int num_keys, const char *keys);