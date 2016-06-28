Murmur LDAP authentication
==========================

This project provides an LDAP-backed server authenticator for Murmur, the
standard Mumble server.

It supports delegating authentication based on usernames and passwords to any
LDAP directory, as well as returning user groups to Murmur.

This makes it possible to, for example, control Murmur's default 'admin' group
through LDAP.

## Building

The project uses [ICE][] to communicate with Murmur based on code generated
at build time.

ICE needs to be installed before you can build this project.

To generate the necessary classes, compile the project and create an uberJAR
simply run `gradle shadowJar`.

## Configuring

A configuration file in Java properties format is expected by the app. The file
should take the following format:

```
# LDAP configuration
ldapHost=127.0.0.1
ldapPort=389
userFilter=(objectClass=*)
usernameAttribute=cn
userBase=ou=users,dc=tendollarbond,dc=com
groupBase=ou=groups,dc=tendollarbond,dc=com
groupMemberAttribute=member

# Murmur / slice configuration
murmurHost=127.0.0.1
murmurPort=6502
murmurSecret=TrumpForPresident2016
```

The keys `ldapHost`, `ldapPort`, `usernameAttribute`, `groupMemberAttribute`,
`murmurHost` and `murmurPort` are optional and default to the values in the
example above.

## Running

Start the service with `java -jar murmur_ldap_auth.jar [config-location]`. If no
configuration file is specified it is expected in the file `murmur-auth.conf` in
the current working directory.

[ICE]: https://github.com/zeroc-ice/ice
