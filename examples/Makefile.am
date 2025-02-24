srcPath = $(srcdir)/../src

bin_PROGRAMS = mtlverify mtlsign mtlkeygen
mtlverify_SOURCES = mtlverify.c  mtltool_io.c mtl_example_util.c
mtlverify_LDADD = $(srcPath)/.libs/libmtllib.a -loqs
mtlsign_SOURCES = mtlsign.c  mtltool_io.c mtl_example_util.c
mtlsign_LDADD = $(srcPath)/.libs/libmtllib.a -loqs
mtlkeygen_SOURCES = mtlkeygen.c  mtltool_io.c mtl_example_util.c
mtlkeygen_LDADD = $(srcPath)/.libs/libmtllib.a -loqs

AM_CFLAGS = -I$(srcPath) $(all_includes)