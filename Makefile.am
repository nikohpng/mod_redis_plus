include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_redis_plus

if HAVE_REDIS_PLUS

mod_LTLIBRARIES = mod_redis_plus.la
mod_redis_plus_la_SOURCES    = redis_plus_pipeline.cpp redis_plus_profile.cpp redis_plus_utils.cpp mod_redis_plus.cpp
mod_redis_plus_la_CFLAGS     = $(AM_CPPFLAGS) $(CPPFLAGS) $(HIREDIS_CFLAGS) -std=gnu++11  
mod_redis_plus_la_CXXFLAGS   = $(AM_CPPFLAGS) $(CPPFLAGS) $(HIREDIS_CFLAGS) -std=gnu++11
mod_redis_plus_la_LDFLAGS    = -avoid-version -module -no-undefined -shared $(FREESWITCH_LIBS) $(OPENSSL_LIBS) $(MOSQUITTO_LIBS) $(REDIS_PLUS_LIBS)
mod_redis_plus_la_LIBADD     = $(switch_builddir)/libfreeswitch.la

else
install: error
all: error
error:
	$(error You must install libredis++-dev to build this module)
endif

