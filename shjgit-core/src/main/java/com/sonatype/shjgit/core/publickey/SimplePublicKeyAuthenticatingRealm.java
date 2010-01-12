package com.sonatype.shjgit.core.publickey;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.security.PublicKey;
import java.util.*;

/**
 * Shiro {@link org.apache.shiro.realm.Realm} for authenticating {@link java.security.PublicKey}s.
 * Authorization is delegated to an {@link org.apache.shiro.authz.Authorizer},
 * which can be a different {@code Realm}.
 * This implementation stores accounts internally in memory. For other storage
 * options, it is advisable to subclass this and override {@link #addAccount(Object, java.util.Set)},
 * {@link #hasAccount(Object)} and {@link #getPublicKeysForAccount(Object)}.
 */
public class SimplePublicKeyAuthenticatingRealm extends AuthenticatingRealm {

    private static final Class<PublicKeyAuthenticationToken> AUTHENTICATION_TOKEN_CLASS = PublicKeyAuthenticationToken.class;
    private        final Map<Object, Set<PublicKey>>         accounts                   = new HashMap<Object, Set<PublicKey>>(); //principal-to-publickeys
    private        final Authorizer                          authorizer;

    /**
     * Constructs this realm, accepting an {@code Authorizer} to which all
     * authorization will be delegated.
     *
     * @param authorizer all authorization will be delegated to this. can be
     * for example another {@link org.apache.shiro.realm.Realm}.
     */
    public SimplePublicKeyAuthenticatingRealm(Authorizer authorizer) {
        setAuthenticationTokenClass(AUTHENTICATION_TOKEN_CLASS);
        setCredentialsMatcher(new PublicKeyCredentialsMatcher());
        this.authorizer = authorizer;
    }

    /**
     * Convenience method for adding an account with only one key.
     * @see #addAccount(Object, java.util.Set)
     * @param principal the account's principal
     * @param key the key this account is allowed to authenticate with
     */
    public void addAccount(Object principal, PublicKey key){
        final HashSet<PublicKey> publicKeys = new HashSet<PublicKey>(1);
        publicKeys.add(key);
        addAccount(principal, publicKeys);
    }

    /**
     * Adds an account with a set of keys the account is allowed to authenticate
     * with.
     * @param principal the account's principal
     * @param keys the keys this account is allowed to authenticate with
     */
    public void addAccount(Object principal, Set<PublicKey> keys){
        accounts.put(principal, keys);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        final Object principal = token.getPrincipal();

        if ( !hasAccount(principal)){
            return null;
        }

        return new SimpleAuthenticationInfo(principal, getPublicKeysForAccount(principal), getName());
    }

    /**
     * Retrieves an account's {@link PublicKey}s.
     * This should be overridden by subclasses which store accounts differently.
     * @param principal the principal to look up.
     * @return a set of keys with which the account is allowed to authenticate.
     */
    protected Set<PublicKey> getPublicKeysForAccount(Object principal) {
        return accounts.get(principal);
    }

    /**
     * Checks to see if this realm has an account with the supplied principal.
     * This should be overridden by subclasses which store accounts differently.
     * @param principal the principal to look for. 
     * @return {@code true} is the account is known, {@code false} otherwise.
     */
    protected boolean hasAccount(Object principal) {
        return accounts.containsKey(principal);
    }

    //-------------------------------------------------------------------------
    // Delegating all authorization
    //-------------------------------------------------------------------------

    @Override
    public boolean isPermitted(PrincipalCollection principals, String permission) {
        return authorizer.isPermitted(principals, permission);
    }

    @Override
    public boolean isPermitted(PrincipalCollection subjectPrincipal, Permission permission) {
        return authorizer.isPermitted(subjectPrincipal, permission);
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, String... permissions) {
        return authorizer.isPermitted(subjectPrincipal, permissions);
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, List<Permission> permissions) {
        return authorizer.isPermitted(subjectPrincipal, permissions);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, String... permissions) {
        return authorizer.isPermittedAll(subjectPrincipal, permissions);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) {
        return authorizer.isPermittedAll(subjectPrincipal, permissions);
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, String permission) throws AuthorizationException {
        authorizer.checkPermission(subjectPrincipal, permission);
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, Permission permission) throws AuthorizationException {
        authorizer.checkPermission(subjectPrincipal, permission);
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, String... permissions) throws AuthorizationException {
        authorizer.checkPermissions(subjectPrincipal, permissions);
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) throws AuthorizationException {
        authorizer.checkPermissions(subjectPrincipal, permissions);
    }

    @Override
    public boolean hasRole(PrincipalCollection subjectPrincipal, String roleIdentifier) {
        return authorizer.hasRole(subjectPrincipal, roleIdentifier);
    }

    @Override
    public boolean[] hasRoles(PrincipalCollection subjectPrincipal, List<String> roleIdentifiers) {
        return authorizer.hasRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public boolean hasAllRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) {
        return authorizer.hasAllRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public void checkRole(PrincipalCollection subjectPrincipal, String roleIdentifier) throws AuthorizationException {
        authorizer.checkRole(subjectPrincipal, roleIdentifier);
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) throws AuthorizationException {
        authorizer.checkRoles(subjectPrincipal, roleIdentifiers);
    }

}
