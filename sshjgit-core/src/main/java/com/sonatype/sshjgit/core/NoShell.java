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
package com.sonatype.sshjgit.core;

import org.apache.sshd.common.Factory;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.eclipse.jgit.lib.Constants;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Dummy shell which prints a message and terminates. */
class NoShell implements Factory<Command> {
    @Override
    public Command create() {
        return new Command() {
            private InputStream in;
            private OutputStream out;
            private OutputStream err;
            private ExitCallback exit;

            @Override
            public void setInputStream( InputStream in ) {
                this.in = in;
            }

            @Override
            public void setOutputStream( OutputStream out ) {
                this.out = out;
            }

            @Override
            public void setErrorStream( OutputStream err ) {
                this.err = err;
            }

            @Override
            public void setExitCallback( ExitCallback callback ) {
                this.exit = callback;
            }

            @Override
            public void start( Environment env ) throws IOException {
                err.write( Constants.encodeASCII( "sshjgit: no shell available\n" ) );
                in.close();
                out.close();
                err.close();
                exit.onExit( 127 );
            }

            @Override
            public void destroy() {
            }
        };
    }
}