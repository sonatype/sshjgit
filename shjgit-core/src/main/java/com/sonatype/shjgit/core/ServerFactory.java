package com.sonatype.shjgit.core;

import com.sonatype.shjgit.core.publickey.ShiroSecurityManagerPublickeyAuthenticator;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.util.Arrays;

/**
 * Simple {@link SshServer} which serves Git repositories.
 * 
 * @author hugo@josefson.org
 */
public class ServerFactory {
    /**
     * Constructs a default configured {@link SshServer} for serving up Git repositories.
     *
     * @param configDir directory where ssh server keys will be loaded/saved. {@code null} if they should not be loaded/saved.
     * @param port which port the ssh server should bind to.
     * @param securityManager the Shiro {@code SecurityManager} which you have preconfigured for authenticating users.
     * @return an {@code SshServer}, ready for you to {@link org.apache.sshd.SshServer#start()}. Please {@link org.apache.sshd.SshServer#stop()} it when it's time for your application to shut down.
     */
    public SshServer createDefaultServer(String configDir, int port, SecurityManager securityManager) {
        final SshServer server = SshServer.setUpDefaultServer();

        server.setPort( port );
        server.setKeyPairProvider( createHostKeyProvider( configDir ) );
        server.setShellFactory( new NoShell() );
        server.setCommandFactory( new GitCommandFactory() );
        server.setUserAuthFactories( Arrays.<NamedFactory<UserAuth>>asList(
                new UserAuthPublicKey.Factory( ),
                new ShiroSecurityManagerUserAuthPassword.Factory( securityManager )
        ) );

        final PublickeyAuthenticator publickeyAuthenticator = new ShiroSecurityManagerPublickeyAuthenticator( securityManager );
        server.setPublickeyAuthenticator( publickeyAuthenticator );

        return server;
    }

    private SimpleGeneratorHostKeyProvider createHostKeyProvider( String configDir ) {
        if ( configDir == null ){
            return new SimpleGeneratorHostKeyProvider( null );
        }else{
            return new SimpleGeneratorHostKeyProvider( configDir + "/shjgit.hostkeys" );
        }
    }
}
