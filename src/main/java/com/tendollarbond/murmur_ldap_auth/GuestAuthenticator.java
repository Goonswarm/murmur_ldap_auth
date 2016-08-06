package com.tendollarbond.murmur_ldap_auth;

import Ice.StringHolder;
import Murmur.GroupNameListHolder;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.template.mustache.MustacheTemplateEngine;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import static com.tendollarbond.murmur_ldap_auth.LDAPAuthenticator.usernameToId;
import static spark.Spark.get;
import static spark.Spark.post;

/**
 * This class contains an endpoint to provide guest access to a Mumble server protected by LDAP authentication.
 *
 * Guest accesses can be created via the /mumble/create URI which should be protected by something external to this
 * server. If present, the X-User header is used to identify and log who created a guest session.
 *
 * TODO: Configurable Mumble URL.
 */
public class GuestAuthenticator implements Runnable {
    final private Logger logger = LoggerFactory.getLogger(this.getClass());
    final private SecureRandom random = new SecureRandom();

    /** User information, i.e. password hash and session ID. */
    final private class UserData {
        final public String session;
        final public String passwordHash;

        private UserData(String session, String passwordHash) {
            this.session = session;
            this.passwordHash = passwordHash;
        }
    }

    /** A concurrent, expiring cache for tracking users. */
    final private Cache<String, UserData> guestMap = CacheBuilder.newBuilder()
            .expireAfterWrite(4, TimeUnit.HOURS)
            .build();

    /** A concurrent, expiring cache that tracks active guest sessions. */
    final private Cache<String, LocalDateTime> sessionMap = CacheBuilder.newBuilder()
            .expireAfterWrite(4, TimeUnit.HOURS)
            .build();

    @Override
    public void run() {
        // Admin routes
        get("/mumble/guests", this::showAdminForm, new MustacheTemplateEngine());
        post("/mumble/guests", this::createGuestLink);

        // User routes
        get("/mumble/visit/:session", this::showSessionPage, new MustacheTemplateEngine());
        post("/mumble/visit", this::createGuestLogin, new MustacheTemplateEngine());
    }

    /** Displays a page on which an administrator can create a guest access token with limited validity.
     * This results in a link which can be shared with external guests in order to grant them access.
     * */
    private ModelAndView showAdminForm(Request request, Response response) {
        return new ModelAndView(new HashMap<>(), "create.html");
    }

    /** Creates a new guest link entry and redirects the user to the link. */
    private Object createGuestLink(Request request, Response response) {
        final String sessionToken = new BigInteger(130, random).toString(32);
        final LocalDateTime expiry = LocalDateTime.now().plusHours(4);
        final String user = request.headers("REMOTE_USER");

        logger.info("Guest session created by {}", user);
        sessionMap.put(sessionToken, expiry);
        response.redirect("/mumble/visit/" + sessionToken, 303);
        return new Object();
    }

    /** Displays the page on which a user can enter the name with which they want to connect to Mumble. */
    private ModelAndView showSessionPage(Request request, Response response) {
        final String sessionToken = request.params(":session");
        final Map<String, String> model = ImmutableMap.of("alert", "", "session", sessionToken);
        return new ModelAndView(model, "visit.html");
    }

    /** Verifies a user's POSTed session and creates a temporary login for them if the session has not expired. */
    private ModelAndView createGuestLogin(Request request, Response response) {
        final String session = request.queryParams("session");
        final String username = request.queryParams("username");

        // Check for duplicate usernames and session expiry before letting a user in.
        if (guestMap.asMap().containsKey(username)) {
            logger.info("Duplicate username attempt: {}", username);
            final Map<String, String> model = ImmutableMap.of("alert", "Username already taken.", "session", session);
            return new ModelAndView(model, "visit.html");
        } else if (sessionMap.asMap().getOrDefault(session, LocalDateTime.MAX).isAfter(LocalDateTime.now())) {
            final String password = new BigInteger(130, random).toString(32).substring(0, 20);
            final String mumbleLink = String.format("mumble://%s:%s@127.0.0.1/?version=1.2.0", username, password);
            final Map<String, String> model = ImmutableMap.of(
                    "username", username,
                    "password", password,
                    "session", session,
                    "mumbleLink", mumbleLink
            );

            logger.info("Creating guest login for {}", username);
            guestMap.put(username, new UserData(session, BCrypt.hashpw(password, BCrypt.gensalt())));

            return new ModelAndView(model, "success.html");
        } else {
            logger.info("Invalid or expired guest link from user {}", username);
            final Map<String, String> model = ImmutableMap.of("alert", "Invalid or expired guest link.", "session", "");
            return new ModelAndView(model, "visit.html");
        }
    }

    /** Murmur authentication function callback */
    public int authenticate(String name, String password, StringHolder newName, GroupNameListHolder groups) {
        if (authenticateGuest(name, password)) {
            logger.info("Successful guest login from {}", name);

            // Set guests group to allow separate Mumble permissions for guests.
            final String[] guestGroup = {"guests"};
            groups.value = guestGroup;

            // Prefix  name to make it obvious who is a guest
            newName.value = String.format("[spai] %s", name);

            return usernameToId(name);
        }

        // Murmur authentication failure
        return -1;
    }

    /** Method to check whether user credentials are valid guest credentials. */
    private boolean authenticateGuest(String username, String password) {
        final UserData userData = guestMap.asMap().get(username);
        if ((userData != null) && (BCrypt.checkpw(password, userData.passwordHash))) {
            final LocalDateTime sessionExpiry = sessionMap.asMap().getOrDefault(userData.session, LocalDateTime.MAX);
            return sessionExpiry.isAfter(LocalDateTime.now());
        }
        return false;
    }

    public static void main(String[] args) {
        new GuestAuthenticator().run();
    }
}
