# LDAP Authentication plug-in

This is a simple LDAP authentication plug-in for Mirth Connect. It can be used
to allow users to login using an LDAP service for authentication and authorization.

You can also fall-back to using the local Mirth user-database if you'd like if
no acceptable user can be located in the LDAP service.

## Configuration

Configuration is done using a simple Java properties file, `ldap.properties`,
which you place on your server alongside your `mirth.properties` file. A sample
file is included in this directory, and it contains comments describing each
configuration settings.

## Installation

Simply upload the ZIP file containing the plug-in via the Mirth Connect
administrator, or unzip the ZIP file into the `extensions/` directory on
your Mirth server.

## Building

The LDAP authenticator can be built with Apache Maven, but it will require that
you obtain a few libraries manually, since Mirth Connect does not public Maven
artifacts. You will need to place these files into the `libs/` directory:

    mirth-server.jar

You can find these libraries in Mirth Connect's server download.
