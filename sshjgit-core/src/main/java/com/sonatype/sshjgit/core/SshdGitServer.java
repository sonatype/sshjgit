package com.sonatype.sshjgit.core;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import com.sonatype.sshjgit.core.gitcommand.GitCommandFactory;
import com.sonatype.sshjgit.core.security.ShiroAwareSshServerSessionFactory;
import com.sonatype.sshjgit.core.security.ShiroPublickeyAuthenticator;
import com.sonatype.sshjgit.core.security.ShiroUserAuthPassword;

// Pluggable transport, can I use anything but SSHD right now? SmartHTTPS?
// Pluggable security manager

@Singleton
@Named("sshd")
public class SshdGitServer {
    
    @Inject
    private SecurityManager securityManager;
    
    private File repositoriesDirectory;
    
    private File configDir;
    
    private int port;
    
    private SshServer server;
    
    @Inject
    public SshdGitServer( int port, File configDir, File repositoriesDirectory, SecurityManager securityManager ) {
        this.port = port;
        this.configDir = configDir;
        this.repositoriesDirectory = repositoriesDirectory;
        this.securityManager = securityManager;
    }

    /**
     * Constructs a default configured {@link SshServer} for serving up Git repositories.
     *
     * @param port which port the ssh server should bind to.
     * @param reposRootDirectory where the git repositories are stored
     * @param securityManager the Shiro {@code SecurityManager} which you have preconfigured for authenticating users.
     * @param hostKeyProvider provider of this server's ssh host keys
     * @return an {@code SshServer}, ready for you to {@link org.apache.sshd.SshServer#start()}. Please {@link org.apache.sshd.SshServer#stop()} it when it's time for your application to shut down.
     */
    public SshServer createDefaultServer() {

        SimpleGeneratorHostKeyProvider hostKeyProvider;
        
        if ( configDir == null ){
            hostKeyProvider =  new SimpleGeneratorHostKeyProvider( null );
        }else{
            hostKeyProvider = new SimpleGeneratorHostKeyProvider( configDir + "/sshjgit.hostkeys" );
        }
        
        SshServer server = SshServer.setUpDefaultServer();
        server.setPort( port );
        server.setKeyPairProvider( hostKeyProvider );
        server.setShellFactory( new NoShell() );
        server.setCommandFactory( new GitCommandFactory( repositoriesDirectory ) );
        server.setUserAuthFactories( Arrays.<NamedFactory<UserAuth>>asList( new UserAuthPublicKey.Factory(), new ShiroUserAuthPassword.Factory()) );
        server.setSessionFactory( new ShiroAwareSshServerSessionFactory( securityManager, server ) );
        server.setPublickeyAuthenticator( new ShiroPublickeyAuthenticator());        
        return server;
    }
    
    //
    // Lifecycle
    //
    public void start() throws IOException {
        
        server.start();

        Runtime.getRuntime().addShutdownHook( new Thread() {
            @Override
            public void run() {
                try {
                    server.stop();
                } catch (InterruptedException ignore) {
                }
            }
        } );
    }
    
    public void stop() {        
    }
}
