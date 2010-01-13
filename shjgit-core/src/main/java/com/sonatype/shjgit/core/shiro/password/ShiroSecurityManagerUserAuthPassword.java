package com.sonatype.shjgit.core.shiro.password;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.session.ServerSession;

/**
 * A {@link UserAuth} that delegates to a Shiro {@link SecurityManager} for
 * authentication by password.
 *
 * @author <a href="mailto:peter.royal@pobox.com">peter royal</a>
 */
public class ShiroSecurityManagerUserAuthPassword implements UserAuth {
    public static final Session.AttributeKey<Subject> SUBJECT = new Session.AttributeKey<Subject>();

    private final SecurityManager securityManager;

    public static class Factory implements NamedFactory<UserAuth> {
        private final SecurityManager securityManager;

        public Factory( SecurityManager securityManager ) {
            this.securityManager = securityManager;
        }

        @Override
        public String getName() {
            return "password";
        }

        @Override
        public UserAuth create() {
            return new ShiroSecurityManagerUserAuthPassword( securityManager );
        }
    }

    public ShiroSecurityManagerUserAuthPassword( SecurityManager securityManager ) {
        this.securityManager = securityManager;
    }

    @Override
    public Boolean auth( ServerSession session, String username, Buffer buffer ) throws Exception {
        boolean newPassword = buffer.getBoolean();
        if ( newPassword ) {
            throw new IllegalStateException( "Password changes are not supported" );
        }
        String password = buffer.getString();

        try {
            Subject subject = securityManager.getSubject();
            subject.login( new UsernamePasswordToken( username, password ) );

            session.setAttribute( SUBJECT, subject );

            return true;
        } catch( AuthenticationException e ) {
            throw new Exception( "Authentication failed: bad username or password supplied", e );
        }

    }
}
