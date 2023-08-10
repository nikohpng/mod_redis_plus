# mod_redis_plus
FreeSWITCH connect to redis with cluster and sentinel model

## Dependency
Before installing, you need to install [hiredis](https://github.com/sewenew/redis-plus-plus/tree/fb020fa1f6e116738cda2dfcbb064a5320664b4a#install-hiredis) and [redis-plus-plus](https://github.com/sewenew/redis-plus-plus/tree/fb020fa1f6e116738cda2dfcbb064a5320664b4a#install-redis-plus-plus)

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
