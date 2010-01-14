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
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Basic command implementation invoked by {@link GitCommandFactory}. */
abstract class AbstractCommand implements Command, SessionAware {
    private static final Logger log =
        LoggerFactory.getLogger( AbstractCommand.class );

    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected ExitCallback exit;
    protected ServerSession session;
    private String name;
    private String[] args;

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
    public void setSession( ServerSession session ) {
        this.session = session;
    }

    protected String getName() {
        return name;
    }

    void parseArguments( String cmdName, String line ) {
        List<String> list = new ArrayList<String>();
        boolean inquote = false;
        StringBuilder r = new StringBuilder();
        for ( int ip = 0; ip < line.length(); ) {
            char c = line.charAt( ip++ );
            switch( c ) {
                case '\t':
                case ' ':
                    if ( inquote ) {
                        r.append( c );
                    } else if ( r.length() > 0 ) {
                        list.add( r.toString() );
                        r = new StringBuilder();
                    }
                    continue;
                case '\'':
                    inquote = !inquote;
                    continue;
                case '\\':
                    if ( inquote || ip == line.length() ) {
                        r.append( c ); // literal within a quote
                    } else {
                        r.append( line.charAt( ip++ ) );
                    }
                    continue;
                default:
                    r.append( c );
            }
        }
        if ( r.length() > 0 ) {
            list.add( r.toString() );
        }
        name = cmdName;
        args = list.toArray( new String[list.size()] );
    }

    @Override
    public void start(Environment env) {
        final String who = session.getUsername();
        new Thread( "Execute " + getName() + " [" + who + "]" ) {
            @Override
            public void run() {
                runImp();
            }
        }.start();
    }

    private void runImp() {
        int rc = 0;
        try {
            try {
                try {
                    run( args );
                } catch( IOException e ) {
                    if ( e.getClass().equals( IOException.class )
                         && "Pipe closed".equals( e.getMessage() ) ) {
                        // This is sshd telling us the client just dropped off while
                        // we were waiting for a read or a write to complete. Either
                        // way its not really a fatal error. Don't log it.
                        //
                        throw new UnloggedFailure( 127, "error: client went away", e );
                    }

                    throw new Failure( 128, "fatal: unexpected IO error", e );

                } catch( RuntimeException e ) {
                    throw new Failure( 128, "fatal: internal server error", e );

                } catch( Error e ) {
                    throw new Failure( 128, "fatal: internal server error", e );

                }
            } catch( Failure e ) {
                if ( !( e instanceof UnloggedFailure ) ) {
                    StringBuilder logmsg = beginLogMessage();
                    logmsg.append( ": " );
                    logmsg.append( e.getMessage() );
                    if ( e.getCause() != null ) {
                        log.error( logmsg.toString(), e.getCause() );
                    } else {
                        log.error( logmsg.toString() );
                    }
                }

                rc = e.exitCode;
                try {
                    err.write( ( e.getMessage() + '\n' ).getBytes( "UTF-8" ) );
                } catch( IOException ignored ) {
                }
            }
        } finally {
            try {
                out.flush();
            } catch( IOException ignored ) {
            }

            try {
                err.flush();
            } catch( IOException ignored ) {
            }

            exit.onExit( rc );
        }
    }

    private StringBuilder beginLogMessage() {
        StringBuilder logmsg = new StringBuilder();
        logmsg.append( "sshd error: " );
        logmsg.append( name );
        for ( String a : args ) {
            logmsg.append( ' ' );
            logmsg.append( a );
        }
        return logmsg;
    }

    protected abstract void run( String[] args ) throws IOException, Failure;

    public static class Failure extends Exception {
        final int exitCode;

        public Failure( int exitCode, String msg ) {
            this( exitCode, msg, null );
        }

        public Failure( int exitCode, String msg, Throwable why ) {
            super( msg, why );
            this.exitCode = exitCode;
        }
    }

    public static class UnloggedFailure extends Failure {
        public UnloggedFailure( int exitCode, String msg ) {
            this( exitCode, msg, null );
        }

        public UnloggedFailure( int exitCode, String msg, Throwable why ) {
            super( exitCode, msg, why );
        }
    }
}