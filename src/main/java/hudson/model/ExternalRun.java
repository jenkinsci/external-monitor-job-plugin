/*
 * The MIT License
 * 
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.model;

import hudson.Proc;
import hudson.util.DecodingStream;
import hudson.util.DualOutputStream;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.InputStream;
import java.io.Reader;
import java.util.zip.GZIPInputStream;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import static javax.xml.stream.XMLStreamConstants.*;

/**
 * {@link Run} for {@link ExternalJob}.
 * 
 * @author Kohsuke Kawaguchi
 */
public class ExternalRun extends Run<ExternalJob,ExternalRun> {
    /**
     * Loads a run from a log file.
     * @param owner
     * @param runDir
     */
    ExternalRun(ExternalJob owner, File runDir) throws IOException {
        super(owner,runDir);
    }

    /**
     * Creates a new run.
     * @param project
     */
    ExternalRun(ExternalJob project) throws IOException {
        super(project);
    }

    /**
     * Instead of performing a build, run the specified command,
     * record the log and its exit code, then call it a build.
     * @param cmd   command to run as a build
     */
    public void run(final String[] cmd) {
        execute(new RunExecution() {
            public Result run(BuildListener listener) throws Exception {
                Proc proc = new Proc.LocalProc(cmd,getEnvironment(listener),System.in,new DualOutputStream(System.out,listener.getLogger()));
                return proc.join()==0?Result.SUCCESS:Result.FAILURE;
            }

            public void post(BuildListener listener) {
                // do nothing
            }

            public void cleanUp(BuildListener listener) {
                // do nothing
            }
        });
    }

    private void setCharset(String c) { // JENKINS-14107
        charset = c;
    }

    /**
     * Instead of performing a build, accept the log and the return code
     * from a remote machine.
     *
     * <p>
     * The format of the XML is:
     *
     * <pre>&lt;xmp&gt;
     * &lt;run&gt;
     *  &lt;log&gt;...console output...&lt;/log&gt;
     *  &lt;result&gt;exit code&lt;/result&gt;
     * &lt;/run&gt;
     * &lt;/xmp&gt;</pre>
     *
     * @param in    Log file referenc
     * @throws IOException
     */
    @SuppressWarnings({"Since15"})
    @IgnoreJRERequirement
    @SuppressFBWarnings
    public void acceptRemoteSubmission(final Reader in) throws IOException {
        final long[] duration = new long[1];
        execute(new RunExecution() {
            private String elementText(XMLStreamReader r) throws XMLStreamException {
                StringBuilder buf = new StringBuilder();
                while(true) {
                    int type = r.next();
                    if(type== CHARACTERS || type== CDATA)
                        buf.append(r.getTextCharacters(), r.getTextStart(), r.getTextLength());
                    else
                        return buf.toString();
                }
            }

            @SuppressFBWarnings
            public Result run(BuildListener listener) throws Exception {
                PrintStream logger = new PrintStream(new DecodingStream(listener.getLogger()));

                XMLInputFactory xif = XMLInputFactory.newInstance();
                XMLStreamReader p = xif.createXMLStreamReader(in);

                p.nextTag();    // get to the <run>
                p.nextTag();    // get to the <log>

                try {
                    setCharset(p.getAttributeValue(null,"content-encoding"));
                    while(p.next()!= END_ELEMENT) {
                        int type = p.getEventType();
                        if(type== CHARACTERS || type== CDATA)
                            logger.print(p.getText());
                    }
                    p.nextTag(); // get to <result>
                } catch (Exception ex) {
                    throw ex;
                }

                Result r = Integer.parseInt(elementText(p))==0?Result.SUCCESS:Result.FAILURE;

                do {
                    p.nextTag();
                    if(p.getEventType()== START_ELEMENT){
                        if(p.getLocalName().equals("duration")) {
                            duration[0] = Long.parseLong(elementText(p));
                        }
                        else if(p.getLocalName().equals("displayName")) {
                            setDisplayName(p.getElementText());
                        }
                        else if(p.getLocalName().equals("description")) {
                            setDescription(p.getElementText());
                        }
                    }
                } while(!(p.getEventType() == END_ELEMENT && p.getLocalName().equals("run")));

                return r;
            }

            public void post(BuildListener listener) {
                // do nothing
            }

            public void cleanUp(BuildListener listener) {
                // do nothing
            }
        });

        if(duration[0]!=0) {
            super.duration = duration[0];
            // save the updated duration
            save();
        }
    }

    /**
     * @param result    Result code of the external job
     * @param duration  Duration (in milliseconds) of the external job run
     * @param stream    Stream of external job log
     * @throws IOException
     */
    @SuppressFBWarnings
    public void acceptRemoteSubmission(final int result, final long duration, final InputStream stream) throws IOException {
        execute(new RunExecution() {
            public Result run(BuildListener listener) throws Exception {
                PrintStream logger = new PrintStream(listener.getLogger());
                final int sChunk = 8192;
                GZIPInputStream zipin = new GZIPInputStream(stream);
                byte[] buffer = new byte[sChunk];
                int length;
                try {
                    while ((length = zipin.read(buffer, 0, sChunk)) != -1)
                        logger.write(buffer, 0, length);
                } catch (Exception ex) {
                    throw ex;
                } 
                Result r = result==0?Result.SUCCESS:Result.FAILURE;
                return r;
            }

            public void post(BuildListener listener) {
                // do nothing
            }

            public void cleanUp(BuildListener listener) {
                // do nothing
            }
        });

        super.duration = duration;
        save();
    }

    /**
     * @param result    Result code of the external job
     * @param duration  Duration (in milliseconds) of the external job run
     * @param log       External job log
     * @throws IOException
     */
    @SuppressFBWarnings
    public void acceptRemoteSubmission(final int result, final long duration, final String log) throws IOException {
        execute(new RunExecution() {
            public Result run(BuildListener listener) throws Exception {
                PrintStream logger = new PrintStream(listener.getLogger());
                try {
                    logger.print(log);
                } catch (Exception ex) {
                    throw ex;
                }
                Result r = result==0?Result.SUCCESS:Result.FAILURE;
                return r;
            }

            public void post(BuildListener listener) {
                // do nothing
            }

            public void cleanUp(BuildListener listener) {
                // do nothing
            }
        });

        super.duration = duration;
        save();
    }

}
