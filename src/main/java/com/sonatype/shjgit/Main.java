package com.sonatype.shjgit;

import java.util.Collections;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.jsecurity.cache.HashtableCacheManager;
import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.realm.SimpleAccountRealm;

/**
 * Main entry point
 *
 * @author <a href="mailto:peter.royal@pobox.com">peter royal</a>
 */
public class Main {

    public static void main( String... args ) throws Exception {
        final SshServer server = SshServer.setUpDefaultServer();

        server.setPort( 2222 );
        server.setKeyPairProvider( new SimpleGeneratorHostKeyProvider() );
        server.setShellFactory( new NoShell() );
        server.setCommandFactory( new GitCommandFactory() );
        server.setUserAuthFactories( Collections.<NamedFactory<UserAuth>>singletonList(
            new JSecurityManagerAuthenticator.Factory( createSecurityManager() ) ) );

        server.start();

        Runtime.getRuntime().addShutdownHook( new Thread() {
            @Override
            public void run() {
                server.stop();
            }
        } );
    }

    private static SecurityManager createSecurityManager() {
        SimpleAccountRealm realm = new SimpleAccountRealm();

        realm.init();

        DefaultSecurityManager securityManager = new DefaultSecurityManager( realm );

        securityManager.setCacheManager( new HashtableCacheManager() );

        realm.addAccount( System.getProperty( "user.name" ), "test", "shjgit" );

        return securityManager;
    }
}
