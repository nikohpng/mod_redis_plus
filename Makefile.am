include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_redis_plus

mod_LTLIBRARIES = mod_redis_plus.la
mod_redis_plus_la_SOURCES    = redis_plus_pipeline.cpp redis_plus_profile.cpp redis_plus_utils.cpp mod_redis_plus.cpp
mod_redis_plus_la_CFLAGS     = $(AM_CPPFLAGS) $(CPPFLAGS) -std=gnu++11 -D_FILE_OFFSET_BITS=64 -I/usr/local/include -I/usr/local/include/hiredis
mod_redis_plus_la_CXXFLAGS   = $(AM_CPPFLAGS) $(CPPFLAGS) -std=gnu++11 -D_FILE_OFFSET_BITS=64 -I/usr/local/include -I/usr/local/include/hiredis
mod_redis_plus_la_LDFLAGS    = -avoid-version -module -no-undefined -shared $(FREESWITCH_LIBS) $(OPENSSL_LIBS) $(MOSQUITTO_LIBS) -L/usr/local/lib64 -L/usr/local/lib -lredis++ -lhiredis
mod_redis_plus_la_LIBADD     = $(switch_builddir)/libfreeswitch.la
