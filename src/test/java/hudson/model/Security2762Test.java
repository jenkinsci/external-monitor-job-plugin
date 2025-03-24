package hudson.model;

import org.htmlunit.Page;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.net.HttpURLConnection;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

@WithJenkins
class Security2762Test {

    @Issue("SECURITY-2762")
    @Test
    void doPostBuildResultWhenInvokedUsingGetMethodThenResourceNotFound(JenkinsRule j) throws Exception {
        j.jenkins.createProject(ExternalJob.class, "externalJob");
        JenkinsRule.WebClient webClient = j .createWebClient().withThrowExceptionOnFailingStatusCode(false);
        Page page = webClient.goTo("job/externalJob/postBuildResult");

        assertThat(page.getWebResponse().getStatusCode(), is(HttpURLConnection.HTTP_NOT_FOUND));
        assertThat(page.getWebResponse().getContentAsString(), containsString("Stapler processed this HTTP request as follows, but couldn't find the resource to consume the request"));
    }
}
