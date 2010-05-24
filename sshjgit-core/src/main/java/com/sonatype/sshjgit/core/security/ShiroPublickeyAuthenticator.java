package com.sonatype.sshjgit.core.security;

import java.security.PublicKey;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.subject.Subject;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.sonatype.security.realms.publickey.PublicKeyAuthenticationToken;

/**
 * A {@link PublickeyAuthenticator} that delegates to Shiro for authentication by {@link PublicKey}.
 *
 * @author hugo@josefson.org
 */
public class ShiroPublickeyAuthenticator implements PublickeyAuthenticator{

    @Override
    public boolean authenticate(String username, final PublicKey key, ServerSession session) {
        try {
            final Subject subject = SecurityUtils.getSubject();
            subject.login( new PublicKeyAuthenticationToken( username, key ) );
            return true;
        } catch( AuthenticationException e ) {
            return false;
        }

    }


}