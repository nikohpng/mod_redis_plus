# mod_redis_plus
FreeSWITCH connect to redis with cluster and sentinel model

## Dependency
Before installing, you need to install [hiredis](https://github.com/sewenew/redis-plus-plus/tree/master#install-hiredis) and [redis-plus-plus](https://github.com/sewenew/redis-plus-plus/tree/master#install-redis-plus-plus)

  > redis-plus-plus must compile by c++11

when you done it, you need run this to check it:
```shell
pkg-config --list-all | grep redis++
pkg-config --list-all | grep hiredis
```
## Install
+ Copy the following content to your configure.ac
  ```
  PKG_CHECK_MODULES([HIREDIS], [hiredis >= 0.10.0],[
  AM_CONDITIONAL([HAVE_HIREDIS],[true])],[
  AC_MSG_RESULT([no]); AM_CONDITIONAL([HAVE_HIREDIS],[false])])

  PKG_CHECK_MODULES([REDIS_PLUS], [redis++ >= 1.3.0],[
  AM_CONDITIONAL([HAVE_REDIS_PLUS],[true])],[
  AC_MSG_RESULT([no]); AM_CONDITIONAL([HAVE_REDIS_PLUS],[false])])
  ```
+ Modify modules.conf in freeswitch source, add `applications/mod_redis_plus`
+ Clone source mod_redis_plus to `src/mod/application/`
  ```
  git clone https://github.com/nikohpng/mod_redis_plus ./src/mod/application/
  ```
+ Run `rebootstrap.sh` or `bootstrap.sh` to rebuild Makefile.in
+ If everything is ok, you can do `./configure && make && make install`
+ Add mod_redis_plus to freeswitch/conf/autoload/modules.conf.xml
+ Add autoload_conf/redis_plus.conf.xml to freeswitch/conf/autoload_configs
## Configuration
+ profiles - save multiple profiles
  + profile - it contain all configuration of a connection
  + connection - a connection name
  + hostname - a connection ip address, `localhost` by default
  + password - this connnection password
  + port - connect to redis port, `6379` by default
  + redis-type - how connect to redis server, [1: single 2: cluster 3: sentinel]
  + ignore-connect-fail - ignore connection fail in profile
  + max_pipelined_requests - pipline request, `20` by default
