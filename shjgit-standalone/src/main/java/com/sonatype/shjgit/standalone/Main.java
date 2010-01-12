package com.sonatype.shjgit.standalone;

import com.sonatype.shjgit.core.publickey.SimplePublicKeyAuthenticatingRealm;
import com.sonatype.shjgit.core.ServerFactory;
import org.apache.commons.io.FileUtils;
import org.apache.mina.util.Base64;
import org.apache.shiro.cache.DefaultCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.util.Buffer;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

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

    private static SecurityManager createSecurityManager() throws NoSuchProviderException, InvalidKeySpecException, NoSuchAlgorithmException, IOException {
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

    private static PublicKey loadDefaultPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        List<String> lines = FileUtils.readLines(new File(System.getProperty("user.home") + "/.ssh/id_rsa.pub"));
        final String base64encodedKey = extractKeyPart(lines.get(0));
        return new Buffer(Base64.decodeBase64(base64encodedKey.getBytes())).getPublicKey();
    }

    /**
     * Extracts the key part from a id_rsa.pub file.
     * @param idRsaPubLine an enitire line of text from a public key file, such as id_rsa.pub
     * @return just the long base64 encoded part in the middle
     */
    private static String extractKeyPart(String idRsaPubLine) {
        return idRsaPubLine.split(" ")[1];
    }

}
