package com.sonatype.sshjgit.core;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.sonatype.security.realms.publickey.PublicKeyAuthenticatingRealm;
import org.sonatype.security.realms.publickey.SimplePublicKeyRepository;

import com.sonatype.sshjgit.core.security.RolePermissionsAwareSimpleAccountRealm;
import com.sonatype.sshjgit.core.util.SshKeyUtils;

@Singleton
@Named("default")
public class GitSecurityManager extends DefaultSecurityManager {
    
    @Inject
    public GitSecurityManager( Collection<Realm> realms ) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        
        super();
                                
        String username = System.getProperty("user.name");

        //
        // this realm can authenticate passwords, and is considered the one which should perform authorization
        //
        RolePermissionsAwareSimpleAccountRealm simpleAccountRealm = new RolePermissionsAwareSimpleAccountRealm("simpleAccountRealm");
        simpleAccountRealm.init();
        simpleAccountRealm.add(new SimpleRole( "developer", createSampleGroupPermissions() ));
        simpleAccountRealm.add(new SimpleAccount( username, "test", "simpleAccountRealm", Collections.<String>singleton("developer"), createSampleUserPermissions(username)));

        //
        // this realm contains allowed public keys for each username. it delegates all authorization to the realm injected in its constructor.
        //
        SimplePublicKeyRepository simplePublicKeyRepository = new SimplePublicKeyRepository();
        simplePublicKeyRepository.addPublicKey(username, loadDefaultPublicKey());
        PublicKeyAuthenticatingRealm publicKeyRealm = new PublicKeyAuthenticatingRealm(simplePublicKeyRepository);

        // put both realms in the SecurityManager, so either can authenticate a user
        setRealms( Arrays.<Realm>asList( simpleAccountRealm, publicKeyRealm ));
        setCacheManager( new MemoryConstrainedCacheManager() );
    }
    
    private PublicKey loadDefaultPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        final File file = new File(System.getProperty("user.home") + "/.ssh/id_dsa.pub");
        return SshKeyUtils.toPublicKey(file);
    }

    private Set<Permission> createSampleGroupPermissions() {
        return new HashSet<Permission>() {
            {
                // allows normal push to all existing project repos, i.e. /projects/**
                add(new WildcardPermission("gitrepo:push:projects"));

                // allows fetch (pull) from all existing project repos
                add(new WildcardPermission("gitrepo:fetch:projects"));
            }
        };
    }

    private Set<Permission> createSampleUserPermissions(final String username) {
        return new HashSet<Permission>() {
            {
                // allows creating new repos under their own directory, i.e. /users/hugo/**
                add(new WildcardPermission("gitrepo:new:users:"+username));

                // allows permission to non-fast-forward heads in all their own repos
                add(new WildcardPermission("gitrepo:non-fast-forward:users:"+username));

                // allows normal push to all their own repos
                add(new WildcardPermission("gitrepo:push:users:"+username));

                // allows fetch (pull) from all their own repos
                add(new WildcardPermission("gitrepo:fetch:users:"+username));

                // all of these could be simplified as:
                // add(new WildcardPermission("gitrepo:*:users:"+username));
            }
        };
    }    
}
