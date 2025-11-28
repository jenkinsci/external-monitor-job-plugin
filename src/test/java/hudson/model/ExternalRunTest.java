package hudson.model;

import hudson.EnvVars;
import hudson.util.StreamTaskListener;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author Kohsuke Kawaguchi
 */
@WithJenkins
class ExternalRunTest {

    @Test
    void test1(JenkinsRule jenkins) throws Exception {
        ExternalJob p = jenkins.createProject(ExternalJob.class, "test");
        ExternalRun b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log content-encoding='UTF-8'>AAAAAAAA</log><result>0</result><duration>100</duration></run>"
        ));
        assertEquals(Result.SUCCESS, b.getResult());
        assertEquals(100, b.getDuration());

        b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log content-encoding='UTF-8'>AAAAAAAA</log><result>1</result></run>"
        ));
        assertEquals(Result.FAILURE, b.getResult());
    }

    @Test
    void testStringResult(JenkinsRule jenkins) throws Exception {
        ExternalJob p = jenkins.createProject(ExternalJob.class);
        ExternalRun b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log/><result>SUCCESS</result></run>"
        ));
        assertEquals(Result.SUCCESS, b.getResult());

        b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log/><result>ABORTED</result></run>"
        ));
        assertEquals(Result.ABORTED, b.getResult());
    }

    @Issue("JENKINS-11592")
    @Test
    void testExternalJob(JenkinsRule jenkins) throws Exception {
        ExternalJob p = jenkins.createProject(ExternalJob.class);
        ExternalRun b = p.newBuild();
        b.acceptRemoteSubmission(new StringReader(
            "<run><log content-encoding='UTF-8'></log><result>0</result><duration>1</duration></run>"
        ));

        assertGetEnvironmentWorks(b);
    }

    @SuppressWarnings("rawtypes")
    private static void assertGetEnvironmentWorks(Run build) throws Exception {
        whenJenkinsMasterHasNoExecutors();
        // and getEnvironment is called outside of build
        EnvVars envVars =  build.getEnvironment(StreamTaskListener.fromStdout());
        // then it should still succeed - i.e. no NPE o.s.l.t.
        assertNotNull(envVars);
    }

    private static void whenJenkinsMasterHasNoExecutors() throws Exception {
        Jenkins.get().setNumExecutors(0);
        // force update of nodes (TODO https://github.com/jenkinsci/jenkins/pull/1596 renders this workaround unnecessary):
        Jenkins.get().setNodes(Jenkins.get().getNodes());
    }
}
