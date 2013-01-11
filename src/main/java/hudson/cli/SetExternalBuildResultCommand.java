package hudson.cli;

import jenkins.model.Jenkins;
import hudson.Extension;
import hudson.model.ExternalJob;
import hudson.model.ExternalRun;
import hudson.model.Run;
import hudson.model.Item;
import hudson.remoting.Callable;
import org.apache.commons.io.IOUtils;
import org.kohsuke.args4j.Option;

import java.io.IOException;
import java.io.Serializable;
import java.io.InputStream;

/**
 * Set build result for external monitor job.
 *
 * @author David Ostrovsky
 */
@Extension
public class SetExternalBuildResultCommand extends CLICommand implements Serializable {

    @Override
    public String getShortDescription() {
        return "Set external monitor job result.";
    }

    @Option(name="--job", aliases={"-j"}, metaVar="JOB", usage="Name of the external monitor job", required=true)
    public transient String job;

    @Option(name="--display", aliases={"-n"}, metaVar="DISPLAY", usage="Display name of the job", required=false)
    public transient String displayName;

    @Option(name="--result", aliases={"-r"}, metaVar="RESULT", usage="0: true, 1: false", required=true)
    public transient int result;

    @Option(name="--duration", aliases={"-d"}, metaVar="DURATIOn", usage="Duration", required=false)
    public transient long duration = 0;

    @Option(name="--log", aliases={"-l"}, metaVar="-|LOG", required=true, usage="Log to be set. '-' to read from stdin (gzipped).")
    public String log;

    /**
     * Entry point to the SetExternalBuildResultCommand command.
     *
     * <p>
     * Schedule an external build, put passed build result and return the build number.
     * If log is '-' then gzipped stream is expected on stdin, otherwise it is raw string
     * (not BASE64 encoded).
     *
     * @return
     *      new build number.
     */
    protected int run() throws Exception {
        Item item = Jenkins.getInstance().getItem(job);
        if (!(item instanceof ExternalJob)) {
            throw new IllegalStateException("non external monitor job: " + job);
        }
        ExternalJob extJob = (ExternalJob)item;
        ExternalRun run = extJob.newBuild();
        run.checkPermission(Run.UPDATE);

        if ("-".equals(log)) {
            run.acceptRemoteSubmission(result, duration, stdin);
        } else {
            run.acceptRemoteSubmission(result, duration, log);
        }

        if (displayName != null) {
            run.setDisplayName(displayName);
        }

        return run.getNumber();
    }

}
