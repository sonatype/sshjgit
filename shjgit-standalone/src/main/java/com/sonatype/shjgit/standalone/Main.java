package com.sonatype.shjgit.standalone;

import com.sonatype.shjgit.core.publickey.SimplePublicKeyAuthenticatingRealm;
import com.sonatype.shjgit.core.ServerFactory;
import org.apache.mina.util.Base64;
import org.apache.shiro.cache.DefaultCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.util.Buffer;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Main entry point
 *
 * // TODO: This class should either be made more generic, or be considered a sample.
 *
 * @author <a href="mailto:peter.royal@pobox.com">peter royal</a>
 */
public class Main {
    private static final String CONFIG_DIR = System.getProperty("user.dir");

    public static void main( String... args ) throws Exception {

        final SecurityManager securityManager = createSecurityManager();
        final SshServer server = new ServerFactory().createDefaultServer(
                CONFIG_DIR, 2222, securityManager );

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

    private static SecurityManager createSecurityManager() throws NoSuchProviderException, InvalidKeySpecException, NoSuchAlgorithmException {
        final String username = System.getProperty("user.name");

        SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm("simpleAccountRealm");
        simpleAccountRealm.init();
        simpleAccountRealm.addAccount(username, "test");

        SimplePublicKeyAuthenticatingRealm simplePublicKeyAuthenticatingRealm = new SimplePublicKeyAuthenticatingRealm(simpleAccountRealm);
        simplePublicKeyAuthenticatingRealm.addAccount(username, loadDefaultPublicKey());

        DefaultSecurityManager securityManager = new DefaultSecurityManager( Arrays.<Realm>asList( simpleAccountRealm, simplePublicKeyAuthenticatingRealm));

        securityManager.setCacheManager( new DefaultCacheManager() );

        return securityManager;
    }

    private static PublicKey loadDefaultPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        return new Buffer(Base64.decodeBase64("this would be the base64 encoded string from inside the id_rsa.pub file".getBytes())).getPublicKey();
    }

}
