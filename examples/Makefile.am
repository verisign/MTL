srcPath = $(srcdir)/../src

bin_PROGRAMS = mtlverify mtlsign mtlkeygen
mtlverify_SOURCES = mtlverify.c mtl_example_util.c
mtlverify_LDADD = $(srcPath)/.libs/libmtllib.a -loqs
mtlsign_SOURCES = mtlsign.c mtl_example_util.c
mtlsign_LDADD = $(srcPath)/.libs/libmtllib.a -loqs
mtlkeygen_SOURCES = mtlkeygen.c mtl_example_util.c
mtlkeygen_LDADD = $(srcPath)/.libs/libmtllib.a -loqs

AM_CFLAGS = -I$(srcPath) $(all_includes)