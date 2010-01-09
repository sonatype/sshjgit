package com.sonatype.shjgit;

import java.util.Collections;

import org.apache.shiro.cache.DefaultCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

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
            new ShiroSecurityManagerAuthenticator.Factory( createSecurityManager() ) ) );

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

    private static SecurityManager createSecurityManager() {
        SimpleAccountRealm realm = new SimpleAccountRealm();

        realm.init();

        DefaultSecurityManager securityManager = new DefaultSecurityManager( realm );

        securityManager.setCacheManager( new DefaultCacheManager() );

        realm.addAccount( System.getProperty( "user.name" ), "test", "shjgit" );

        return securityManager;
    }
}
