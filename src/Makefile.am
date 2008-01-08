AM_CFLAGS=$(LSJA_CFLAGS)
MOSTLYCLEANFILES = com_microsoft_sqlserver_jdbc_AuthenticationJNI.h
BUILT_SOURCES = com_microsoft_sqlserver_jdbc_AuthenticationJNI.h

lib_LTLIBRARIES = libsqljdbc_auth.la
libsqljdbc_auth_la_SOURCES = sqljdbc_auth.c
libsqljdbc_auth_la_LDFLAGS = -release $(VERSION)

com_microsoft_sqlserver_jdbc_AuthenticationJNI.h: $(SQLJDBC_JAR)
	$(JAVAH) -classpath $(SQLJDBC_JAR) -jni com.microsoft.sqlserver.jdbc.AuthenticationJNI

