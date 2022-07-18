package hudson.model;

import com.gargoylesoftware.htmlunit.Page;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

import java.net.HttpURLConnection;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

public class Security2762Test {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Issue("SECURITY-2762")
    @Test
    public void doPostBuildResultWhenInvokedUsingGetMethodThenResourceNotFound() throws Exception {
        j.jenkins.createProject(ExternalJob.class, "externalJob");
        JenkinsRule.WebClient webClient = j .createWebClient().withThrowExceptionOnFailingStatusCode(false);
        Page page = webClient.goTo("job/externalJob/postBuildResult");

        assertThat(page.getWebResponse().getStatusCode(), is(HttpURLConnection.HTTP_NOT_FOUND));
        assertThat(page.getWebResponse().getContentAsString(), containsString("Stapler processed this HTTP request as follows, but couldn't find the resource to consume the request"));
    }
}
