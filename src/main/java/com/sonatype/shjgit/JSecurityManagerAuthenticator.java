package com.sonatype.shjgit;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.session.ServerSession;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.subject.Subject;

/**
 * A {@link PasswordAuthenticator} that delegates to a JSecurity {@link SecurityManager}
 *
 * @author <a href="mailto:peter.royal@pobox.com">peter royal</a>
 */
public class JSecurityManagerAuthenticator implements UserAuth {
    public static final Session.AttributeKey<Subject> SUBJECT = new Session.AttributeKey<Subject>();

    private final org.jsecurity.mgt.SecurityManager securityManager;

    public static class Factory implements NamedFactory<UserAuth> {
        private final org.jsecurity.mgt.SecurityManager securityManager;

        public Factory( org.jsecurity.mgt.SecurityManager securityManager ) {
            this.securityManager = securityManager;
        }

        @Override
        public String getName() {
            return "password";
        }

        @Override
        public UserAuth create() {
            return new JSecurityManagerAuthenticator( securityManager );
        }
    }

    public JSecurityManagerAuthenticator( org.jsecurity.mgt.SecurityManager securityManager ) {
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
            Subject subject = securityManager.login( new UsernamePasswordToken( username, password ) );

            session.setAttribute( SUBJECT, subject );

            return true;
        } catch( AuthenticationException e ) {
            throw new Exception( "Authentication failed: bad username or password supplied", e );
        }

    }
}
