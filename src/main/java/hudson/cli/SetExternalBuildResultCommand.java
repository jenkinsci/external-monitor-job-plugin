package hudson.cli;

import hudson.Extension;
import hudson.model.ExternalJob;
import hudson.model.ExternalRun;
import hudson.model.Run;
import hudson.model.TopLevelItem;
import org.kohsuke.args4j.Option;


/**
 * Set build result for external monitor job.
 *
 * @author David Ostrovsky
 */
@Extension
public class SetExternalBuildResultCommand extends CLICommand {

    @Override
    public String getShortDescription() {
        return "Set external monitor job result.";
    }

    @Option(name="--job", aliases={"-j"}, metaVar="JOB", usage="Name of the external monitor job", required=true)
    public transient TopLevelItem job;

    @Option(name="--display", aliases={"-n"}, metaVar="DISPLAY", usage="Display name of the build", required=false)
    public transient String displayName;

    @Option(name="--result", aliases={"-r"}, metaVar="RESULT", usage="0: success, 1: fail", required=false)
    public transient int result = 0;

    @Option(name="--duration", aliases={"-d"}, metaVar="DURATION", usage="Number of milli-seconds it took to run this build", required=false)
    public transient long duration = 0;

    @Option(name="--log", aliases={"-l"}, metaVar="-|LOG", usage="Log to be set. '-' to read from stdin (gzipped).", required=true)
    public String log;

    @Option(name="--dump-build-number", aliases={"-b"}, usage="Log the produced build number to the standard output", required=false)
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
     * @throws Exception
     */
    protected int run() throws Exception {
        ExternalRun run = ((ExternalJob) job).newBuild();
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
            stdout.println(run.getNumber());
        }

        return 0;
    }

}
