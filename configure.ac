# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Autoconf requirements
AC_PREREQ(2.59)

# Autoconf/Automake initialization
AC_INIT(libsqljdbc_auth, 0.1, Dino.DaiZovi@gmail.com)
AC_CONFIG_SRCDIR([src/sqljdbc_auth.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE
AM_DISABLE_STATIC

# information on the package

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_CPP
AC_PROG_JAVAH

AS_IF([test "x$JAVAH" = x],
   AC_MSG_FAILURE(Can't find javah ))

# Checks for libraries.
AC_CHECK_LIB([gssapi_krb5], [gss_init_sec_context])
AC_CHECK_LIB([gssapi], [gss_init_sec_context])
#AC_CHECK_LIB([ntlm], [builtSmbNtlmAuthRequest])

function abspath() {
    absdir=$(cd `dirname $1` && pwd)
    absfile=`basename $1`
    echo -n "$absdir/$absfile"
}


# Check for the Microsoft sqljdbc.jar file
AC_ARG_WITH([sqljdbc],
    [AS_HELP_STRING([--with-sqljdbc],
    [location of Microsoft SQL Server 2005 JDBC driver @<:@default="sqljdbc.jar"@:>@])],
    [],
    [with_sqljdbc=sqljdbc.jar])

# If sqljdbc.jar isn't found, search the CLASSPATH environment variable
AC_CHECK_FILE($with_sqljdbc,[],
    [for cp in `echo $CLASSPATH | sed -e 's/:/ /g'`; do
         cpbase=`basename $cp`
         AS_IF([test $cpbase = "sqljdbc.jar"],
             [with_sqljdbc=$cp; break ])
     done])

# If we still haven't found it, abort configure script
AC_CHECK_FILE($with_sqljdbc,
    [AC_SUBST([SQLJDBC_JAR], $(abspath $with_sqljdbc))],
    [AC_MSG_FAILURE("Can't find Microsoft SQL Server 2005 JDBC driver")])

# Checks for header files.
AC_HEADER_STDC
AC_JNI_INCLUDE_DIR
for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
do
    CPPFLAGS="$CPPFLAGS -I$JNI_INCLUDE_DIR"
done

AC_CHECK_HEADERS([gssapi.h gssapi/gssapi_krb5.h],,[ac_do_krb5="yes"])
#AC_CHECK_HEADERS([ntlm.h],,[ac_do_ntlm="yes"])

# Check that at least one of KRB5 or NTLM is possible
AS_IF([(test "x$ac_do_krb5" != x && test "x$ac_do_ntlm" != x)],
    AC_MSG_FAILURE("No supported authentication methods were found"))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.

# Write output
AC_OUTPUT
