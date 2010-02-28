// Copyright (C) 2008 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package com.sonatype.sshjgit.core.gitcommand;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.eclipse.jgit.lib.PersonIdent;
import org.eclipse.jgit.transport.ReceivePack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/** Receives change upload over SSH using the Git receive-pack protocol. */
class Receive extends AbstractGitCommand {
    private static final Logger log = LoggerFactory.getLogger( Receive.class );

    Receive(File reposRootDir) {
        super(reposRootDir);
    }

    @Override
    protected void runImpl() throws IOException, Failure {
        final Subject subject = SecurityUtils.getSubject();
        subject.checkPermission("gitrepo:push:" + getRepoNameAsPermissionParts(repo));
        ReceivePack rp = new ReceivePack( repo );
        rp.setAllowCreates( true );
        final boolean mayNonFastForward = subject.isPermitted("gitrepo:non-fast-forward:" + getRepoNameAsPermissionParts(repo));
        rp.setAllowDeletes( mayNonFastForward );
        rp.setAllowNonFastForwards( mayNonFastForward );
        rp.setCheckReceivedObjects( true );
        // TODO make this be a real email address!
        final String name;
        final Object principal = subject.getPrincipal();
        if ( principal == null ){
            name = "null_principal";
            log.warn( "principal was null when trying to setRefLogIdent on repo." );
        }else{
            name = principal.toString();
        }
        log.info("setting LogIdent to " + name);
        rp.setRefLogIdent( new PersonIdent(name, name + "@example.com" ) );
        rp.receive( in, out, err );
    }

    @Override
    protected String parseCommandLine( String[] args ) throws Failure {
        if ( 0 != args.length - 1 ) {
            throw usage();
        }
        return args[0];
    }

    private Failure usage() {
        StringBuilder builder = new StringBuilder();
        builder.append( "usage: " );
        builder.append( getName() );
        builder.append( " '/project.git'" );
        return new Failure( 1, builder.toString() );
    }

    @Override
    public void destroy() {
    }
}