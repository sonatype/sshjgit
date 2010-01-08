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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import org.apache.sshd.server.ShellFactory;
import org.spearce.jgit.lib.Constants;

/** Dummy shell which prints a message and terminates. */
class NoShell implements ShellFactory {
    @Override
    public Shell createShell() {
        return new Shell() {
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
            public void start( Map<String, String> env ) throws IOException {
                err.write( Constants.encodeASCII( "shjgit: no shell available\n" ) );
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