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
    public transient ExternalJob job;

    @Option(name="--display", aliases={"-n"}, metaVar="DISPLAY", usage="Display name of the job", required=false)
    public transient String displayName;

    @Option(name="--result", aliases={"-r"}, metaVar="RESULT", usage="0: success, 1: fail", required=true)
    public transient int result;

    @Option(name="--duration", aliases={"-d"}, metaVar="DURATION", usage="Number of milli-seconds it took to run this build", required=false)
    public transient long duration = 0;

    @Option(name="--log", aliases={"-l"}, metaVar="-|LOG", usage="Log to be set. '-' to read from stdin (gzipped).", required=true)
    public String log;

    @Option(name="--dump-build-number", aliases={"-b"}, metaVar="BUILD", usage="Log the produced build number to the standard output", required=false)
    public boolean dumpBuildNumber;

    /**
     * Entry point to the SetExternalBuildResultCommand command.
     *
     * <p>
     * Schedule an external build, put passed build result.
     * If log is '-' then gzipped stream is expected on stdin, otherwise it is raw string
     * (not BASE64 encoded).
     *
     * If -dump-build-number is set, the new created build number dumped to the stdout
     *
     * @return
     *      0: success.
     */
    protected int run() throws Exception {
        ExternalRun run = job.newBuild();
        run.checkPermission(Run.UPDATE);

        if ("-".equals(log)) {
            run.acceptRemoteSubmission(result, duration, stdin);
        } else {
            run.acceptRemoteSubmission(result, duration, log);
        }

        if (displayName != null) {
            run.setDisplayName(displayName);
        }

        if (dumpBuildNumber) {
            System.out.format("%d\n", run.getNumber());
        }

        return 0;
    }

}
