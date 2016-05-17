/*
 * The MIT License
 * 
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi, id:cactusman
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.RunMap.Constructor;
import hudson.util.AlternativeUiTextProvider;
import java.io.File;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.externalmonitorjob.Messages;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

/**
 * Job that runs outside Hudson whose result is submitted to Hudson
 * (either via web interface, or simply by placing files on the file system,
 * for compatibility.)
 *
 * @author Kohsuke Kawaguchi
 */
public class ExternalJob extends ViewJob<ExternalJob,ExternalRun> implements TopLevelItem {

    public ExternalJob(String name) {
        this(Jenkins.getInstance(),name);
    }

    public ExternalJob(ItemGroup parent, String name) {
        super(parent,name);
    }

    @Override
    protected void reload() {
        this.runs.load(this,new Constructor<ExternalRun>() {
            public ExternalRun create(File dir) throws IOException {
                return new ExternalRun(ExternalJob.this,dir);
            }
        });
    }

    // keep track of the previous time we started a build
    private transient long lastBuildStartTime;

    /**
     * Creates a new build of this project for immediate execution.
     *
     * Needs to be synchronized so that two {@link #newBuild()} invocations serialize each other.
     */
    @SuppressFBWarnings(value = "SWL_SLEEP_WITH_LOCK_HELD", justification = "Interrupt-driven code")
    public synchronized ExternalRun newBuild() throws IOException {
        checkPermission(AbstractProject.BUILD);
        // make sure we don't start two builds in the same second
        // so the build directories will be different too
        long timeSinceLast = System.currentTimeMillis() - lastBuildStartTime;
        if (timeSinceLast < 1000) {
            try {
                Thread.sleep(1000 - timeSinceLast);
            } catch (InterruptedException e) {
                //Do nothing
            }
        }
        lastBuildStartTime = System.currentTimeMillis();

        ExternalRun run = new ExternalRun(this);
        _getRuns();
        runs.put(run);
        return run;
    }

    /**
     * Used to check if this is an external job and ready to accept a build result.
     */
    public void doAcceptBuildResult(StaplerResponse rsp) throws IOException, ServletException {
        checkPermission(AbstractProject.BUILD);
        rsp.setStatus(HttpServletResponse.SC_OK);
    }

    /**
     * Used to post the build result from a remote machine.
     */
    public void doPostBuildResult( StaplerRequest req, StaplerResponse rsp ) throws IOException, ServletException {
        ExternalRun run = newBuild();
        run.acceptRemoteSubmission(req.getReader());
        rsp.setStatus(HttpServletResponse.SC_OK);
    }

    public TopLevelItemDescriptor getDescriptor() {
        return DESCRIPTOR;
    }

    @Extension
    public static final TopLevelItemDescriptor DESCRIPTOR = new DescriptorImpl();

    @Override
    public String getPronoun() {
        return AlternativeUiTextProvider.get(PRONOUN, this, Messages.ExternalJob_displayName());
    }

    public static final class DescriptorImpl extends TopLevelItemDescriptor {
        public String getDisplayName() {
            return Messages.ExternalJob_displayName();
        }

        /**
         * Needed if it wants External Monitor Jobs are categorized in Jenkins 2.x.
         *
         * TODO: Override when the baseline is upgraded to 2.x
         *
         * @return A string it represents a ItemCategory identifier.
         */
        public String getCategoryId() {
            return "standalone-projects";
        }

        /**
         * Needed if it wants External Monitor Jobs are categorized in Jenkins 2.x.
         *
         * TODO: Override when the baseline is upgraded to 2.x
         *
         * @return A string with the Item description.
         */
        public String getDescription() {
            return Messages.ExternalJob_Description();
        }

        /**
         * Needed if it wants External Monitor Jobs are categorized in Jenkins 2.x.
         *
         * TODO: Override when the baseline is upgraded to 2.x
         *
         * @return A string it represents a URL pattern to get the Item icon in different sizes.
         */
        public String getIconFilePathPattern() {
            return "plugin/external-monitor-job/images/:size/externaljob.png";
        }

        public ExternalJob newInstance(ItemGroup parent, String name) {
            return new ExternalJob(parent,name);
        }
    }
}
