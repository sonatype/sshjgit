package com.sonatype.shjgit.core.publickey;

import org.apache.shiro.authz.Authorizer;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * {@code PublicKeyAuthenticatingRealm} which stores its accounts in memory.
 *
 * @author hugo@josefson.org
 */
public class SimplePublicKeyAuthenticatingRealm extends AbstractPublicKeyAuthenticatingRealm {

    private final Map<Object, Set<PublicKey>> accounts = new HashMap<Object, Set<PublicKey>>(); //principal-to-publickeys

    /**
     * Constructs this realm, accepting an {@code Authorizer} to which all
     * authorization will be delegated.
     *
     * @param authorizer all authorization will be delegated to this. can be
     *                   for example another {@link org.apache.shiro.realm.Realm}.
     */
    public SimplePublicKeyAuthenticatingRealm(Authorizer authorizer) {
        super(authorizer);
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
    protected Set<PublicKey> getPublicKeysForAccount(Object principal) {
        return accounts.get(principal);
    }

    @Override
    protected boolean hasAccount(Object principal) {
        return accounts.containsKey(principal);
    }

}
