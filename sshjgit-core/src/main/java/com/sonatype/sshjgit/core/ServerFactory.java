package com.sonatype.sshjgit.core;

import com.sonatype.sshjgit.core.gitcommand.GitCommandFactory;
import com.sonatype.sshjgit.core.security.ShiroAwareSshServerSessionFactory;
import com.sonatype.sshjgit.core.security.ShiroPublickeyAuthenticator;
import com.sonatype.sshjgit.core.security.ShiroUserAuthPassword;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.io.File;
import java.util.Arrays;

/**
 * Factory for constructing {@link SshServer}s which serve Git repositories.
 * 
 * @author <a href="mailto:peter.royal@pobox.com">peter royal</a>
 * @author hugo@josefson.org
 */
public class ServerFactory {
    /**
     * Constructs a default configured {@link SshServer} for serving up Git repositories.
     *
     * @param port which port the ssh server should bind to.
     * @param reposRootDirectory where the git repositories are stored
     * @param securityManager the Shiro {@code SecurityManager} which you have preconfigured for authenticating users.
     * @param hostKeyProvider provider of this server's ssh host keys
     * @return an {@code SshServer}, ready for you to {@link org.apache.sshd.SshServer#start()}. Please {@link org.apache.sshd.SshServer#stop()} it when it's time for your application to shut down.
     */
    public SshServer createDefaultServer(int port, File reposRootDirectory, SecurityManager securityManager, KeyPairProvider hostKeyProvider) {
        final SshServer server = SshServer.setUpDefaultServer();

        server.setPort( port );
        server.setKeyPairProvider( hostKeyProvider );
        server.setShellFactory( new NoShell() );
        server.setCommandFactory( new GitCommandFactory( reposRootDirectory ) );
        server.setUserAuthFactories( Arrays.<NamedFactory<UserAuth>>asList(
                new UserAuthPublicKey.Factory( ),
                new ShiroUserAuthPassword.Factory( )
        ) );

        server.setSessionFactory( new ShiroAwareSshServerSessionFactory( securityManager, server ) );

        final PublickeyAuthenticator publickeyAuthenticator = new ShiroPublickeyAuthenticator( );
        server.setPublickeyAuthenticator( publickeyAuthenticator );

        return server;
    }

    /**
     * Constructs a default configured {@link SshServer} for serving up Git repositories.
     *
     * @param port which port the ssh server should bind to.
     * @param reposRootDirectory
     * @param securityManager the Shiro {@code SecurityManager} which you have preconfigured for authenticating users.
     * @param configDir directory where ssh server keys will be loaded/saved. {@code null} if they should not be loaded/saved.
     * @return an {@code SshServer}, ready for you to {@link org.apache.sshd.SshServer#start()}. Please {@link org.apache.sshd.SshServer#stop()} it when it's time for your application to shut down.
     */
    public SshServer createDefaultServer(int port, File reposRootDirectory, SecurityManager securityManager, String configDir) {
        final SimpleGeneratorHostKeyProvider hostKeyProvider = createHostKeyProvider(configDir);
        return createDefaultServer(port, reposRootDirectory, securityManager, hostKeyProvider);
    }

    private SimpleGeneratorHostKeyProvider createHostKeyProvider( String configDir ) {
        if ( configDir == null ){
            return new SimpleGeneratorHostKeyProvider( null );
        }else{
            return new SimpleGeneratorHostKeyProvider( configDir + "/sshjgit.hostkeys" );
        }
    }
}
