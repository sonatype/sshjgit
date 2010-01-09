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

package com.sonatype.shjgit;

import java.io.File;
import java.io.IOException;

import org.jsecurity.subject.Subject;
import org.eclipse.jgit.lib.Repository;

abstract class AbstractGitCommand extends AbstractCommand {
    protected Repository repo;
    protected Subject userAccount;

    @Override
    protected final void run( String[] args ) throws IOException, Failure {
        String projectName = parseCommandLine( args );
        if ( projectName.endsWith( ".git" ) ) {
            // Be nice and drop the trailing ".git" suffix, which we never keep
            // in our database, but clients might mistakenly provide anyway.
            //
            projectName = projectName.substring( 0, projectName.length() - 4 );
        }
        if ( projectName.startsWith( "/" ) ) {
            // Be nice and drop the leading "/" if supplied by an absolute path.
            // We don't have a file system hierarchy, just a flat namespace in
            // the database's Project entities. We never encode these with a
            // leading '/' but users might accidentally include them in Git URLs.
            //
            projectName = projectName.substring( 1 );
        }

        // TODO we don't want to make a new repo every time :)
        repo = new Repository( new File( projectName ) );
        repo.create();

        userAccount = session.getAttribute( JSecurityManagerAuthenticator.SUBJECT );

        try {
            runImpl();
        } finally {
            repo.close();
        }
    }

    protected abstract void runImpl() throws IOException, Failure;

    protected abstract String parseCommandLine( String[] args ) throws Failure;
}