package com.sonatype.shjgit;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.util.Collections;

/**
 * Simple {@link SshServer} which serves Git repositories.
 * 
 * @author hugo@josefson.org
 */
public class ServerFactory {
    public SshServer createDefaultServer(String configDir, int port, SecurityManager securityManager) {
        final SshServer server = SshServer.setUpDefaultServer();

        server.setPort( port );
        server.setKeyPairProvider( new SimpleGeneratorHostKeyProvider(configDir + "/shjgit.hostkeys") );
        server.setShellFactory( new NoShell() );
        server.setCommandFactory( new GitCommandFactory() );
        server.setUserAuthFactories( Collections.<NamedFactory<UserAuth>>singletonList(
            new ShiroSecurityManagerAuthenticator.Factory( securityManager ) ) );

        return server;
    }
}
