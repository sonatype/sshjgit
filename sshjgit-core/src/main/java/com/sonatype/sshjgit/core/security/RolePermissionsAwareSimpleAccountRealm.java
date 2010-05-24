package com.sonatype.sshjgit.core.security;

import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.authz.permission.RolePermissionResolverAware;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>This {@code Realm} is like {@code SimpleAccountRealm}, but it allows
 * groups to have permissions, which are implicitly considered to be applied to
 * members of each group.</p>
 *
 * <p>The {@link #add(SimpleRole)} method has {@code public} access, so you can
 * add {@link SimpleRole}s. They can have {@link Permission}s.</p>
 *
 * <p>The {@link #add(SimpleAccount)} method also has {@code public} access, so
 * you can add {@link SimpleAccount}s. They can have groups as well as specific
 * {@link Permission}s of their own.</p>
 *
 * <p>When an account is member of a group, it is considered to have all
 * {@code Permission}s of the group in addition to its own specific
 * {@code Permission}s.</p>
 * 
 * <p>
 * TODO: actually improve SimpleAccountRealm within the Apache Shiro project.  {@link RolePermissionResolverAware}
 * 
 * TODO: Consider Removing from core, and push into test or a simple/sample project.
 * </p>
 *
 * @author hugo@josefson.org
 */
public class RolePermissionsAwareSimpleAccountRealm extends SimpleAccountRealm {

    public RolePermissionsAwareSimpleAccountRealm() {
    }

    public RolePermissionsAwareSimpleAccountRealm(String name) {
        super(name);
    }

    @Override
    public void add(SimpleRole role) {
        super.add(role);
    }

    @Override
    public void add(SimpleAccount account) {
        super.add(account);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        final SimpleAccount account = super.users.get(getUsername(principals));
        if (account == null){
            return null;
        }else{
            final SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();

            // adds permissions from the roles
            final Collection<String> roleStrings = account.getRoles();
            if (roleStrings != null){
                authorizationInfo.setRoles(new HashSet<String>(roleStrings));
                for (String roleString : roleStrings) {
                    final SimpleRole role = roles.get(roleString);
                    if (role != null){
                        final Set<Permission> rolePermissions = role.getPermissions();
                        if (rolePermissions != null){
                            authorizationInfo.addObjectPermissions(rolePermissions);
                        }
                    }
                }
            }

            // adds string permissions from the account
            final Collection<String> stringPermissions = account.getStringPermissions();
            if (stringPermissions != null){
                authorizationInfo.addStringPermissions(stringPermissions);
            }

            // adds object permissions from the account
            final Collection<Permission> objectPermissions = account.getObjectPermissions();
            if (objectPermissions != null){
                authorizationInfo.addObjectPermissions(objectPermissions);
            }

            return authorizationInfo;
        }
    }
}
