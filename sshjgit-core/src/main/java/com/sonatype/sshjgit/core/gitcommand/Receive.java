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

import java.io.IOException;

import org.eclipse.jgit.lib.PersonIdent;
import org.eclipse.jgit.transport.ReceivePack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Receives change upload over SSH using the Git receive-pack protocol. */
class Receive extends AbstractGitCommand {
    private static final Logger log = LoggerFactory.getLogger( Receive.class );

    @Override
    protected void runImpl() throws IOException, Failure {
        // TODO: Check Subject's permission to push to this repo.
        ReceivePack rp = new ReceivePack( repo );
        rp.setAllowCreates( true );
        // TODO: Check Subject's permission to non-fast-forward. (delete is just an extreme form of non-fast-forward) NOTE: Don't fail if they lack that permission, just set these two to false:
        rp.setAllowDeletes( true );
        rp.setAllowNonFastForwards( true );
        rp.setCheckReceivedObjects( true );
        // TODO make this be a real email address!
        final String name;
        if ( userAccount == null ) {
            name = "null_userAccount";
            log.warn( "userAccount was null when trying to setRefLogIdent on " +
                    "repo." );
        } else {
            final Object principal = userAccount.getPrincipal();
            if ( principal == null ){
                name = "null_principal";
                log.warn( "principal was null when trying to setRefLogIdent " +
                        "on repo." );
            }else{
                name = principal.toString();
            }
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