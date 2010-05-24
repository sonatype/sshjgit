package com.sonatype.sshjgit.core.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.session.ServerSession;

/**
 * A {@link UserAuth} that delegates to Shiro for authentication by password.
 *
 * @author <a href="mailto:peter.royal@pobox.com">peter royal</a>
 */
public class ShiroUserAuthPassword implements UserAuth {

    public static class Factory implements NamedFactory<UserAuth> {

        @Override
        public String getName() {
            return "password";
        }

        @Override
        public UserAuth create() {
            return new ShiroUserAuthPassword();
        }
    }

    @Override
    public Boolean auth( ServerSession session, String username, Buffer buffer ) throws Exception {
        boolean newPassword = buffer.getBoolean();
        if ( newPassword ) {
            throw new IllegalStateException( "Password changes are not supported" );
        }
        String password = buffer.getString();

        try {
            Subject subject = SecurityUtils.getSubject();
            subject.login( new UsernamePasswordToken( username, password ) );
            return true;
        } catch( AuthenticationException e ) {
            throw new Exception( "Authentication failed: bad username or password supplied", e );
        }

    }
}
