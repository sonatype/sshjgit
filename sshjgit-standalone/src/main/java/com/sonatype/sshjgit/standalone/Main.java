package com.sonatype.sshjgit.standalone;

import com.sonatype.sshjgit.core.ServerFactory;
import com.sonatype.sshjgit.core.shiro.publickey.PublicKeyAuthenticatingRealm;
import com.sonatype.sshjgit.core.shiro.publickey.SimplePublicKeyRepository;
import com.sonatype.sshjgit.core.util.SshKeyUtils;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.cache.DefaultCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.sshd.SshServer;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

/**
 * Main entry point
 *
 * // TODO: This class should either be made more generic, or be considered a sample.
 *
 * @author <a href="mailto:peter.royal@pobox.com">peter royal</a>
 */
public class Main {
    private static final String CONFIG_DIR = System.getProperty("user.dir");
    private static final String REPO_DIR   = System.getProperty("user.dir");

    public static void main( String... args ) throws Exception {

        final SecurityManager securityManager = createSecurityManager();
        final SshServer server = new ServerFactory().createDefaultServer(
                2222, new File(REPO_DIR), securityManager, CONFIG_DIR );

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

        // this realm can authenticate passwords, and is considered the one which should perform authorization
        SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm("simpleAccountRealm"){
            {
                //TODO: how else can we put our own SimpleRole implementations (which include Permissions), in the SimpleRealm, if not by doing it like this? SimpleRealm#add(SimpleRole) has procteted access.
                init();
                final HashSet<Permission> permissions = new HashSet<Permission>() {
                    {
                        // allows normal push to all existing project repos, i.e. /projects/**
                        add(new WildcardPermission("gitrepo:push:projects"));

                        // allows fetch (pull) from all existing project repos
                        add(new WildcardPermission("gitrepo:fetch:projects"));


                        
                        // allows creating new repos under their own directory, i.e. /users/hugo/**
                        add(new WildcardPermission("gitrepo:new:users:"+username));

                        // allows permission to non-fast-forward heads in all their own repos
                        add(new WildcardPermission("gitrepo:non-fast-forward:users:"+username));

                        // allows normal push to all their own repos
                        add(new WildcardPermission("gitrepo:push:users:"+username));

                        // allows fetch (pull) from all their own repos
                        add(new WildcardPermission("gitrepo:fetch:users:"+username));
                    }
                };
                add(new SimpleRole("developer", permissions));

                //TODO: doesn't seem to work when just setting role on account, and no specific permissions. for now, also setting permissions directly on account:
                add(new SimpleAccount(username, "test", getName(), Collections.singleton("developer"), permissions));
            }
        };

        // this realm contains allowed public keys for each username. it delegates all authorization to the realm injected in its constructor.
        SimplePublicKeyRepository simplePublicKeyRepository = new SimplePublicKeyRepository();
        simplePublicKeyRepository.addPublicKey(username, loadDefaultPublicKey());
        PublicKeyAuthenticatingRealm publicKeyRealm = new PublicKeyAuthenticatingRealm(simplePublicKeyRepository, simpleAccountRealm);

        // put both realms in the SecurityManager, so either can authenticate a user
        DefaultSecurityManager securityManager = new DefaultSecurityManager( Arrays.<Realm>asList( simpleAccountRealm, publicKeyRealm ));
        securityManager.setCacheManager( new DefaultCacheManager() );
        return securityManager;
    }

    private static PublicKey loadDefaultPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        final File file = new File(System.getProperty("user.home") + "/.ssh/id_rsa.pub");
        return SshKeyUtils.toPublicKey(file);
    }

}
