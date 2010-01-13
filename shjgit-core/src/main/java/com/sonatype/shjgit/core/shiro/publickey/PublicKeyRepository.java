package com.sonatype.shjgit.core.shiro.publickey;

import java.security.PublicKey;
import java.util.Set;

/**
 * Repository for obtaining each user account's {@link java.security.PublicKey}s.
 * An implementation of this interface is required by the
 * {@link com.sonatype.shjgit.core.shiro.publickey.PublicKeyAuthenticatingRealm}.
 *
 * @author hugo@josefson.org
 */
public interface PublicKeyRepository {

    /**
     * Retrieves an account's {@link java.security.PublicKey}s.
     *
     * @param principal the principal to look up.
     * @return a set of keys with which the account is allowed to authenticate.
     */
    Set<PublicKey> getPublicKeysForAccount(Object principal);

    /**
     * Checks to see if this repository has an account with the supplied principal.
     *
     * @param principal the principal to look for.
     * @return {@code true} is the account is known, {@code false} otherwise.
     */
    boolean hasAccount(Object principal);

}
