srcPath = $(srcdir)/../src

bin_PROGRAMS = mtltool
mtltool_SOURCES = mtltool.c mtltool_io.c
mtltool_LDADD = $(srcPath)/.libs/libmtllib.a -loqs

AM_CFLAGS = -I$(srcPath) $(all_includes)
