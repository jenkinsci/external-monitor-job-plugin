package hudson.model;

import hudson.EnvVars;
import hudson.util.StreamTaskListener;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.jvnet.hudson.test.Bug;
import org.jvnet.hudson.test.HudsonTestCase;

import java.io.IOException;
import java.io.StringReader;

/**
 * @author Kohsuke Kawaguchi
 */
public class ExternalRunTest extends HudsonTestCase {
    public void test1() throws Exception {
        ExternalJob p = hudson.createProject(ExternalJob.class, "test");
        ExternalRun b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log content-encoding='UTF-8'>AAAAAAAA</log><result>0</result><duration>100</duration></run>"
        ));
        assertEquals(Result.SUCCESS,b.getResult());
        assertEquals(b.getDuration(),100);

        b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log content-encoding='UTF-8'>AAAAAAAA</log><result>1</result></run>"
        ));
        assertEquals(Result.FAILURE,b.getResult());
    }

    public void testStringResult() throws Exception {
        ExternalJob p = jenkins.createProject(ExternalJob.class, createUniqueProjectName());
        ExternalRun b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log/><result>SUCCESS</result></run>"
        ));
        assertEquals(Result.SUCCESS,b.getResult());

        b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log/><result>ABORTED</result></run>"
        ));
        assertEquals(Result.ABORTED,b.getResult());
    }

    @Bug(11592)
    public void testExternalJob() throws Exception {
        ExternalJob p = jenkins.createProject(ExternalJob.class, createUniqueProjectName());
        ExternalRun b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log content-encoding='UTF-8'></log><result>0</result><duration>1</duration></run>"
        ));

        assertGetEnvironmentWorks(b);
    }

    @SuppressWarnings("rawtypes")
    private void assertGetEnvironmentWorks(Run build) throws IOException, InterruptedException {
        whenJenkinsMasterHasNoExecutors();
        // and getEnvironment is called outside of build
        EnvVars envVars =  build.getEnvironment(StreamTaskListener.fromStdout());
        // then it should still succeed - i.e. no NPE o.s.l.t.
        assertNotNull(envVars);
    }

    private void whenJenkinsMasterHasNoExecutors() throws IOException {
        Jenkins.getInstance().setNumExecutors(0);
        // force update of nodes:
        Jenkins.getInstance().setNodes(Jenkins.getInstance().getNodes());
        Assert.assertNull(Jenkins.getInstance().toComputer());
    }
}
