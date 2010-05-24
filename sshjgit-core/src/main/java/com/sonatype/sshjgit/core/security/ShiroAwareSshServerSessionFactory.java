package com.sonatype.sshjgit.core.security;

import org.apache.mina.core.session.IoSession;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.server.session.SessionFactory;

/**
 * {@code SessionFactory} for using {@link ShiroAwareSshServerSession} in an
 * {@link SshServer}.
 *
 * @see SshServer#setSessionFactory(org.apache.sshd.server.session.SessionFactory)
 * @author hugo@josefson.org
 */
public class ShiroAwareSshServerSessionFactory extends SessionFactory {
    private final SecurityManager securityManager;

    public ShiroAwareSshServerSessionFactory(SecurityManager securityManager, SshServer sshServer) {
        this.securityManager = securityManager;
        setServer(sshServer);
    }

    @Override
    protected AbstractSession createSession(IoSession ioSession) throws Exception {
        return new ShiroAwareSshServerSession(securityManager, this.server, ioSession);
    }
}
