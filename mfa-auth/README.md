# Multi-factor Authentication plug-in

This is a simple multi-factor plug-in which allows you to use e.g.
[TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)
as a second factor after username+password have been successful.

This plug-in is flexible enough to be used with other MFA schemes
(e.g. HOTP) or as a wrapper for any-of-many MFA schemes, but only
TOTP has been implemented at first.

## Configuration

Configuration is done on a per-user basis with a configuration key in the
database. You must place a user preference in the database in the
person_preference table like this:

    INSERT INTO person_preference (person_id, name, value)
      VALUES (id, 'net.christopherschultz.mirth.plugins.auth.mfa-config', '[setup]')
    ;

If a user does not have such a preference, MFA will not be required.

The "[setup]" is a properly-formatted `otpauth` URI which is documented
here:
[https://github.com/google/google-authenticator/wiki/Key-Uri-Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)

The "issuer" can be included or not in the setup string. If it is present,
it will be used as a part of the token prompt on the client.

For now, only the "totp" type is supported.

## Installation

Simply upload the ZIP file containing the plug-in via the Mirth Connect
administrator, or unzip the ZIP file into the `extensions/` directory on
your Mirth server.

## Building

The LDAP authenticator can be built with Apache Maven, but it will require that
you obtain a few libraries manually, since Mirth Connect does not public Maven
artifacts. You will need to place these files into the `libs/` directory:

    mirth-server.jar
    mirth-client-core.jar
    mirth-client.jar
    java-totp-1.0.jar

You can find these libraries in Mirth Connect's server download, except
for `java-totp-1.0.jar` which you will need to fetch from my `java-totp`
repository here:
[https://github.com/ChristopherSchultz/java-totp](https://github.com/ChristopherSchultz/java-totp)
