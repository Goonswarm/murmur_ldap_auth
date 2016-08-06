package com.tendollarbond.murmur_ldap_auth;

import Murmur.GroupNameListHolder;
import com.google.common.collect.Iterables;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.unboundid.ldap.sdk.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * This class is an implementation of the authenticator interface expected by Murmur.
 *
 * User and group lookups are performed according to the specified configuration.
 *
 * Refer to the project documentation for more information.
 */
public class LDAPAuthenticator  {
    private final LDAPConnectionPool connectionPool;
    private final LDAPConfiguration config;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final int MURMUR_AUTH_FAILURE = -1;
    // private final int MURMUR_AUTH_FALLTHROUGH = -2;

    /** Configuration for the LDAP authenticator. */
    public static class LDAPConfiguration {
        final public String ldapHost;
        final public int ldapPort;

        /** The base DN under which user objects are located. Search scope for users is subtree by default. */
        final public String userBase;

        /** The attribute in which the session is stored. */
        final public String usernameAttribute;

        /** The filter by which to restrict user searches. */
        final public String userFilter;

        /** The base DN under which groups are located */
        final public String groupBase;

        /** The attribute in which group objects store member DNs */
        final public String groupMemberAttr;

        public LDAPConfiguration(String ldapHost, int ldapPort, String userBase, String userNameAttribute,
                                 String userFilter, String groupBase, String groupMemberAttr) {
            this.ldapHost = ldapHost;
            this.ldapPort = ldapPort;
            this.userBase = userBase;
            this.usernameAttribute = userNameAttribute;
            this.userFilter = userFilter;
            this.groupBase = groupBase;
            this.groupMemberAttr = groupMemberAttr;
        }
    }

    private LDAPAuthenticator(LDAPConnectionPool connectionPool, LDAPConfiguration config) {
        this.connectionPool = connectionPool;
        this.config = config;
    }

    /** Creates an instance of this class and sets up a connection pool with the configured details. */
    public static LDAPAuthenticator setupAuthenticator(final LDAPConfiguration config) {
        try {
            final LDAPConnection conn = new LDAPConnection(config.ldapHost, config.ldapPort);
            final LDAPConnectionPool pool = new LDAPConnectionPool(conn, 3);
            pool.setCreateIfNecessary(true);

            final LDAPAuthenticator authenticator = new LDAPAuthenticator(pool, config);
            return authenticator;
        } catch (LDAPException e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }

    /** Main authentication function. Returns either -1 for authentication failure, -2 for unknown user (fall through)
     * or the user ID. See the slice definition for more information. */
    public int authenticate(String name, String pw, GroupNameListHolder groupHolder) {
        logger.info("Attempting to authenticate user {}",  name);
        try {
            final Optional<String> userDN = authenticateUser(name, pw);
            if (userDN.isPresent()) {
                logger.info("Successful login from user {}", name);

                /* Holder classes are used by Ice for additional out parameters, modifying the value of the groupHolder
                 * will cause the groups we retrieve from LDAP to be set on the user. */
                final String[] groups = findUserGroups(userDN.get());
                groupHolder.value = groups;

                return usernameToId(name);
            } else {
                logger.info("Invalid LDAP credentials from user {}", name);
                return MURMUR_AUTH_FAILURE;
            }
        } catch (LDAPException e) {
            logger.error("An error occured while authenticating {}: {}", name, e);
            return MURMUR_AUTH_FAILURE;
        }
    }

    /** Attempt to find and authenticate a user. Returns the user's distinguished name if the user is found and
     * authentication succeeds. */
    private Optional<String> authenticateUser(final String username, final String password) throws LDAPException {
        final LDAPConnection connection = connectionPool.getConnection();
        Optional<String> userDN = findUser(connection, username);
        if (userDN.isPresent()) {
            /* The LDAP library throws the same exception type ofr all errors and usually we would want them to
            * propagate up, however in this case if the exception code is 49 (invalid credentials) we need to catch it
            * so that this function works as expected. */
            try {
                connection.bind(userDN.get(), password);
                connectionPool.releaseDefunctConnection(connection);
                return userDN;
            } catch (LDAPException e) {
                e.printStackTrace();
                // LDAP return code 49 means "invalid credentials"
                if (e.getResultCode().intValue() == 49) {
                    return Optional.empty();
                }
                throw e;
            }
        }

        connectionPool.releaseConnection(connection);
        return userDN;
    }

    /** Attempt to find a user using the configured search filter. The DN of the returned user will be used for binding.
     * TODO: Currently this only works if the directory server lets you search through users anonymously. */
    private Optional<String> findUser(final LDAPConnection connection, final String username) throws LDAPException {
        /* Create a filter with the user supplied information and a check for the session in the supplied attribute. */
        final Filter usernameFilter = Filter.createEqualityFilter(config.usernameAttribute, username);
        final Filter userSuppliedFilter = Filter.create(config.userFilter);
        final Filter filter = Filter.createANDFilter(usernameFilter, userSuppliedFilter);

        final SearchResult result = connection.search(config.userBase, SearchScope.SUB, filter);

        if (result.getEntryCount() != 1) {
            return Optional.empty();
        } else {
            final SearchResultEntry entry = Iterables.getFirst(result.getSearchEntries(), null);
            return Optional.of(entry.getDN());
        }

    }

    /** Attempt to find the groups that a user belongs to. Expects group membership to be stored on the group object. */
    private String[] findUserGroups(final String userDN) throws LDAPException {
        final LDAPConnection connection = connectionPool.getConnection();
        final Filter filter =
                Filter.createExtensibleMatchFilter(config.groupMemberAttr, "distinguishedNameMatch", false, userDN);
        final SearchRequest searchRequest = new SearchRequest(config.groupBase, SearchScope.SUB, filter);
        final List<SearchResultEntry> results = connection.search(searchRequest).getSearchEntries();
        connectionPool.releaseConnection(connection);

        final String[] groups = results.stream()
                .map(entry -> entry.getAttributeValue("cn"))
                .collect(Collectors.toList())
                .toArray(new String[results.size()]);

        return groups;
    }

    /* Helper functions */

    /** Create a user ID by hashing the session and taking some of the hash. This should be good enough for most
     * cases. */
    public static int usernameToId(final String username) {
        final HashFunction hashFunction = Hashing.sha1();
        final int hashed = Math.abs(hashFunction.hashString(username, Charset.defaultCharset()).asInt());
        return hashed;
    }
}
