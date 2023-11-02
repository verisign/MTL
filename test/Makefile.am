srcPath = $(srcdir)/../src

TESTS = mtltest
bin_PROGRAMS = mtltest
mtltest_SOURCES = mtltest.c mtltest_spx.c mtltest_spx_funcs.c mtltest_mtl_node_set.c mtltest_mtl.c mtltest_util.c mtltest_buffer.c mtltest_mtl_abstract.c mtltest_mock.c
mtltest_LDADD = $(srcPath)/.libs/libmtllib.a

AM_CFLAGS = -I$(srcPath) $(all_includes)
