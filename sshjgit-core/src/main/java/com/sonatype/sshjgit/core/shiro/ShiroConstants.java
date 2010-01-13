package com.sonatype.sshjgit.core.shiro;

import org.apache.shiro.subject.Subject;
import org.apache.sshd.common.Session;

/**
 * Shiro related constants for this project.
 */
public class ShiroConstants {
    public static final Session.AttributeKey<Subject> SUBJECT = new Session.AttributeKey<Subject>();
}
