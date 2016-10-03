package com.tendollarbond.murmur_ldap_auth;

import Ice.Current;
import Ice.StringHolder;
import Murmur.GroupNameListHolder;
import Murmur.UserInfoMapHolder;
import Murmur._ServerAuthenticatorDisp;

import static com.tendollarbond.murmur_ldap_auth.LDAPAuthenticator.usernameToId;

/**
 * Main authenticator implementation that dispatches to the LDAP and guest authenticators.
 *
 * Several authenticator callbacks have not been implemented as they are not strictly necessary and/or hard to implement
 * with little gain (such as reversing user hashes).
 */
public class MurmurAuthenticator extends _ServerAuthenticatorDisp {
    final private LDAPAuthenticator ldapAuthenticator;
    final private GuestAuthenticator guestAuthenticator;

    public MurmurAuthenticator(LDAPAuthenticator ldapAuthenticator, GuestAuthenticator guestAuthenticator) {
        this.ldapAuthenticator = ldapAuthenticator;
        this.guestAuthenticator = guestAuthenticator;
    }

    /* Active Murmur callbacks */
    @Override
    public int authenticate(String name, String pw, byte[][] certificates, String certhash, boolean certstrong,
                            StringHolder newname, GroupNameListHolder groups, Current __current) {
        // Attempt LDAP authentication first
        final int ldapResult = ldapAuthenticator.authenticate(name, pw, groups);
        if (ldapResult != -1) {
            return ldapResult;
        }

        // Otherwise attempt guest authentication
        return guestAuthenticator.authenticate(name, pw, newname, groups);
    }

    @Override
    public int nameToId(String name, Current __current) {
        return usernameToId(name);
    }

    /* Unused callbacks */

    @Override
    public boolean getInfo(int id, UserInfoMapHolder info, Current __current) {
        return false;
    }

    @Override
    public String idToName(int id, Current __current) {
        return null;
    }

    @Override
    public byte[] idToTexture(int id, Current __current) {
        return new byte[0];
    }
}
