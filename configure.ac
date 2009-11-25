# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(envelope-milter, 1.1.0, arnold@adaniels.nl)

AC_PROG_CC
AC_PROG_INSTALL

CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
LDFLAGS="${LDFLAGS} -L/usr/local/lib -L/usr/lib/libmilter"

AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h unistd.h syslog.h errno.h sys/types.h pwd.h grp.h sys/socket.h sys/stat.h netinet/in.h arpa/inet.h getopt.h pthread.h libmilter/mfapi.h])

AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_SIZE_T

AC_CHECK_FUNCS([daemon setsid getopt_long])

# Check for pthread library.  On some systems it's in libc_r and must
# be invoked via the special -pthread flag; on other systems it's just
# a regular -lpthread library.
AC_CHECK_LIB([c_r],[pthread_create],[LIBS="-pthread $LIBS"],[AC_CHECK_LIB([pthread],[pthread_create])])

# Check for the milter library.  Libmilter uses pthreads, so we have to do this
# check after the pthread one and use the library list it gave us.
AC_CHECK_LIB([milter],[smfi_main],,,$LIBS)

AC_CHECK_FUNCS([smfi_insheader])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
