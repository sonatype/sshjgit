package com.sonatype.shjgit.core.shiro.publickey;

import org.apache.shiro.authc.AuthenticationToken;

import java.security.PublicKey;

/**
 * {@link AuthenticationToken} for a {@link PublicKey}.
 *
 * @author hugo@josefson.org
 */
public class PublicKeyAuthenticationToken implements AuthenticationToken {
    private final Object principal;
    private final PublicKey key;

    public PublicKeyAuthenticationToken(Object principal, PublicKey key) {
        this.principal = principal;
        this.key = key;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public PublicKey getCredentials() {
        return key;
    }
}
