# Introduction #

All configurations require the Microsoft SQL Server 2005 JDBC Driver 1.2 or later, because that is the first version to load a sqljdbc\_auth library for integrated authentication.  Most Unix-like systems and Kerberos implementations should work with both SQL Server 2000 and 2005, but it may take a few releases before most common Linux, BSD, Solaris, and MacOS X environments work out of the box.

# Details #

libsqljdbc\_auth has been successfully built, tested, and used under:
  * SLES 9 SP3, Heimdal Kerberos 1.0.1, and SQL Server 2000 and 2005