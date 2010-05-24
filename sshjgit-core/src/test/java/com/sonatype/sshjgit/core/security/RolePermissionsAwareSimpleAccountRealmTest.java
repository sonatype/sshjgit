package com.sonatype.sshjgit.core.security;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.sonatype.sshjgit.core.security.RolePermissionsAwareSimpleAccountRealm;

/**
 * @author hugo@josefson.org
 */
public class RolePermissionsAwareSimpleAccountRealmTest {
    protected RolePermissionsAwareSimpleAccountRealm realm;
    protected static final String REALM_NAME = "testRealm";
    protected static final String PASSWORD = "password";
    protected static final String USERNAME = "username";
    protected static final SimplePrincipalCollection PRINCIPALS = new SimplePrincipalCollection(USERNAME, REALM_NAME);
    protected static final Set<String> NO_STRINGS = Collections.<String>emptySet();
    protected static final Set<Permission> NO_PERMISSIONS = Collections.<Permission>emptySet();

    @Before
    public void setUp() {
        realm = new RolePermissionsAwareSimpleAccountRealm();
        realm.init();
    }

    @Test
    public void givenNoGroupAndNoPermissionsThenNoPermissions() {
        realm.add(new SimpleAccount(USERNAME, PASSWORD, REALM_NAME, NO_STRINGS, NO_PERMISSIONS));
        final AuthorizationInfo info = realm.doGetAuthorizationInfo(PRINCIPALS);
        Assert.assertTrue(info.getObjectPermissions().isEmpty());
        Assert.assertNull(info.getStringPermissions());
    }
    @Test
    public void givenNoGroupAndStringPermissionsThenSameStringPermissions(){
        final SimpleAccount account = new SimpleAccount(USERNAME, PASSWORD, REALM_NAME);
        final Collection<String> stringPermissions = createStringPermissions(USERNAME);
        account.addStringPermissions(stringPermissions);
        realm.add(account);
        final AuthorizationInfo info = realm.doGetAuthorizationInfo(PRINCIPALS);
        Assert.assertNull(info.getObjectPermissions());
        Assert.assertArrayEquals(stringPermissions.toArray(), info.getStringPermissions().toArray());
    }

    protected Collection<String> createStringPermissions(String username) {
        final HashSet<String> strings = new HashSet<String>();
        strings.add("gitrepo:push:project");
        strings.add("gitrepo:pull:project");
        strings.add("gitrepo:*:users:"+username);
        return strings;

    }

}
