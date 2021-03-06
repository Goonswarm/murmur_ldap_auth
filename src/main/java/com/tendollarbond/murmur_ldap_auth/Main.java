package com.tendollarbond.murmur_ldap_auth;

import Ice.Communicator;
import Ice.ConnectionRefusedException;
import Ice.InitializationData;
import Ice.ObjectAdapter;
import Murmur.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import static com.tendollarbond.murmur_ldap_auth.LDAPAuthenticator.LDAPConfiguration;

/**
 * Murmur authentication handler.
 *
 * This implements an authentication handler that will connect to a running Murmur server through ICE and register
 * itself as an authenticator on all available servers.
 *
 * See project documentation for more information.
 */
public class Main implements Runnable {
    final private Configuration config;
    final private Logger logger = LoggerFactory.getLogger(this.getClass());
    final private GuestAuthenticator guestAuthenticator = new GuestAuthenticator();

    public Main(Configuration configuration) {
        this.config = configuration;
    }

    public static class Configuration {
        final public String murmurHost;
        final public int murmurPort;
        final public String murmurSecret;
        final public LDAPConfiguration ldapConfiguration;
        final public boolean enableGuestAccess;

        private Configuration(String murmurHost, int murmurPort, String murmurSecret, LDAPConfiguration ldapConfiguration, boolean enableGuestAccess) {
            this.murmurHost = murmurHost;
            this.murmurPort = murmurPort;
            this.murmurSecret = murmurSecret;
            this.ldapConfiguration = ldapConfiguration;
            this.enableGuestAccess = enableGuestAccess;
        }
    }

    public static void main(String[] args) throws IOException {
        final Configuration config;

        if (args.length == 0) {
            config = loadConfiguration("murmur-auth.conf");
        } else {
            config = loadConfiguration(args[0]);
        }

        final Main main = new Main(config);
        main.run();
    }

    private static Configuration loadConfiguration(final String configPath) throws IOException {
        final Properties properties = new Properties();
        final Path path = FileSystems.getDefault().getPath(configPath);
        final InputStream inputStream = Files.newInputStream(path);

        if (inputStream != null) {
            properties.load(inputStream);

            // Construct LDAP configuration (all fields must be set)
            final String ldapHost = properties.getProperty("ldapHost", "127.0.0.1");
            final int ldapPort = Integer.parseInt(properties.getProperty("ldapPort", "389"));
            final String ldapUserBase = getPropertyOrFail(properties, "userBase");
            final String ldapUsernameAttr = properties.getProperty("usernameAttribute", "cn");
            final String ldapUserFilter = getPropertyOrFail(properties, "userFilter");
            final String ldapGroupBase = getPropertyOrFail(properties, "groupBase");
            final String ldapGroupMemberAttr = properties.getProperty("groupMemberAttribute", "member");

            final LDAPConfiguration ldapConfiguration = new LDAPConfiguration(ldapHost, ldapPort, ldapUserBase,
                    ldapUsernameAttr, ldapUserFilter, ldapGroupBase, ldapGroupMemberAttr);

            // Construct full configuration object
            final String murmurHost = properties.getProperty("murmurHost", "127.0.0.1");
            final int murmurPort = Integer.parseInt(properties.getProperty("murmurPort", "6502"));
            final String murmurSecret = getPropertyOrFail(properties, "murmurSecret");
            final boolean enableGuestAccess = Boolean.parseBoolean(properties.getProperty("enableGuestAccess", "false"));
            final Configuration configuration =
                    new Configuration(murmurHost, murmurPort, murmurSecret, ldapConfiguration, enableGuestAccess);

            return configuration;

        } else {
            throw new FileNotFoundException("Configuration file " + configPath + " not found.");
        }
    }

    private static String getPropertyOrFail(final Properties properties, final String field) {
        final String value = properties.getProperty(field);
        if (value != null) {
            return value;
        } else {
            throw new RuntimeException("Field " + field + " not set in configuration.");
        }
    }

    /** Creates an Ice Communicator with an implicit context containing the Murmur secret. */
    private Communicator setupCommunicator(final String secret) {
        final Ice.Properties properties = Ice.Util.createProperties();
        properties.setProperty("Ice.ImplicitContext", "Shared");
        final InitializationData data = new InitializationData();
        data.properties = properties;

        final Ice.Communicator communicator = Ice.Util.initialize(data);
        communicator.getImplicitContext().put("secret", secret);
        return communicator;
    }

    /** Prepare the server authenticator and proxy instance to be registered with Murmur. */
    private ServerAuthenticatorPrx prepareAuthenticatorProxy(MurmurAuthenticator authenticator, Communicator communicator) {
        /* Set up adapter & endpoint */
        final ObjectAdapter adapter =
                communicator.createObjectAdapterWithEndpoints("Callback.Client", "tcp -h 127.0.0.1");
        adapter.activate();

        final ServerAuthenticatorPrx authenticatorPrx =
                ServerAuthenticatorPrxHelper.uncheckedCast(adapter.addWithUUID(authenticator));

        return authenticatorPrx;
    }

    /** Register a given authenticator proxy in some servers. */
    private void registerAuthenticator(ServerPrx[] servers, ServerAuthenticatorPrx authenticatorPrx)
            throws InvalidSecretException, ServerBootedException, InvalidCallbackException {
        logger.info("Attaching authenticator to {} servers", servers.length);

        for (ServerPrx server : servers) {
            server.setAuthenticator(authenticatorPrx);
        }
    }

    @Override
    public void run() {
        logger.info("Connecting to Murmur on {}", config.murmurHost);
        final Ice.Communicator communicator = setupCommunicator(config.murmurSecret);
        final String connectionString = String.format("Meta:tcp -h %s -p %d", config.murmurHost, config.murmurPort);
        final Ice.ObjectPrx obj = communicator.stringToProxy(connectionString);

        /* Start the guest endpoint if enabled */
        if (config.enableGuestAccess) {
            logger.info("Starting Spark endpoint for Murmur guest access");
            guestAuthenticator.run();
        }

        /* Create and register authenticator in all existing servers. */
        try {
            /* Prepare authenticator backend */
            final LDAPAuthenticator ldapAuthenticator = LDAPAuthenticator.setupAuthenticator(config.ldapConfiguration);
            final MurmurAuthenticator murmurAuthenticator = new MurmurAuthenticator(ldapAuthenticator, guestAuthenticator);

            /* Prepare authenticator & endpoint for calling it */
            final ServerAuthenticatorPrx authenticatorPrx = prepareAuthenticatorProxy(murmurAuthenticator, communicator);

            /* Downcast to Murmur's meta object for fetching virtual servers. This establishes the connection. */
            final MetaPrx prx = MetaPrxHelper.checkedCast(obj);
            final ServerPrx[] servers = prx.getAllServers();
            registerAuthenticator(servers, authenticatorPrx);
        } catch (InvalidSecretException e) {
            logger.error("Invalid Murmur secret {}", e);
            System.exit(-1);
        } catch (ServerBootedException e) {
            logger.error("Murmur server is not fully booted {}", e);
            System.exit(-1);
        } catch (InvalidCallbackException e) {
            logger.error("Invalid callback implementation: {}", e);
            System.exit(-1);
        } catch (ConnectionRefusedException e) {
            logger.error("Could not connect to Murmur: e", e);
            System.exit(-1);
        }
    }
}
