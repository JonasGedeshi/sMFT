import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;
import org.mockserver.verify.VerificationTimes;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static shaded_package.io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;

public class ICMTest {
    private ClientAndServer mockServer;
    @Before
    public void startMockServer() {
        mockServer = startClientAndServer(1080);
        mockServer.when(request().withMethod("Get")
                .withPath("/op/v1/auth")
                .withQueryStringParameter("client_id","28358814-5c20-4c13-bbff-db5dd8c4ae93")
                //.withQueryStringParameter("redirect_uri","https%3A%2F%2Fmijntoepassing.vlaanderen.be%2Fcallback")
                //.withQueryStringParameter("response_type","code")
                //.withQueryStringParameter("scope","openid%20vo%20profile")
                //.withQueryStringParameter("state","Fheue34eg2hjsdehfk839ed83azz")
                //.withQueryStringParameter("nonce","FJEkzudnsiz34kzlDzl82pzod21sjsy922jdSaq")
                //.withQueryStringParameter("acr_values","urn:be:vlaanderen:authmech:itsme%20urn:be:vlaanderen:authmech:eid%20urn:be:vlaanderen:authmech:csamtotp")
        ).respond(response().withStatusCode(200).withHeader(new Header(CONTENT_TYPE.toString(), "application/json"))
                .withBody("{\"code\":\"OV9FU_1lxJoAbc\",\"state\":\"Fheue34eg2hjsdehfk839ed83azz\"}"));
    }

    @Test
    public void DiscoveryTest() throws URISyntaxException, IOException, InterruptedException {
        Discovery discovery = new Discovery();
        assertEquals(discovery.getAuthorizationEndpoint(),"https://authenticatie-ti.vlaanderen.be/op/v1/auth");
    }

    @Test
    public void AuthorizationTest() throws URISyntaxException, IOException, InterruptedException {
        var client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(new URI("http://localhost:1080/op/v1/auth?client_id=28358814-5c20-4c13-bbff-db5dd8c4ae93")).GET().header("accept", "application/json").build();
        var respons = client.send(request, HttpResponse.BodyHandlers.ofString());

        System.err.println(respons.body());

        mockServer.verify(request().withPath("/op/v1/auth"), VerificationTimes.once());
    }

    @After
    public void stopMockServer() {
        mockServer.stop();
    }
}
