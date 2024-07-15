srcPath = $(srcdir)/../src

bin_PROGRAMS = mtltool mtlverify
mtltool_SOURCES = mtltool.c mtltool_io.c  mtl_example_util.c
mtltool_LDADD = $(srcPath)/.libs/libmtllib.a -loqs
mtlverify_SOURCES = mtlverify.c  mtltool_io.c mtl_example_util.c
mtlverify_LDADD = $(srcPath)/.libs/libmtllib.a -loqs

AM_CFLAGS = -I$(srcPath) $(all_includes)