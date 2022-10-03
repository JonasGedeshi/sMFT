import com.auth0.jwk.JwkException;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;
import org.mockserver.verify.VerificationTimes;
import shaded_package.org.apache.commons.lang3.RandomStringUtils;
import shaded_package.com.nimbusds.jose.JOSEException;
import shaded_package.org.apache.http.auth.AuthenticationException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.security.NoSuchAlgorithmException;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static shaded_package.io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;

public class ICMTest {
    private ClientAndServer mockServer;
    private Map<String, String> stateNonce = new HashMap<>();

    private String getNewNonceState(){
        String nonce = RandomStringUtils.randomAlphanumeric(10);
        String state = RandomStringUtils.randomAlphanumeric(10);

        stateNonce.put(state, nonce);
        return state;
    }

    private void removeNonceState(String state){
        stateNonce.remove(state);
    }

    private void setAuthorizationResponse(String state){
        String nonce = stateNonce.get(state);
        mockServer.when(request().withMethod("Get")
                        .withPath("/op/v1/auth")
                        .withQueryStringParameter("client_id","28358814-5c20-4c13-bbff-db5dd8c4ae93")
                        //.withQueryStringParameter("redirect_uri","https%3A%2F%2Fmijntoepassing.vlaanderen.be%2Fcallback")
                        //.withQueryStringParameter("response_type","code")
                        //.withQueryStringParameter("scope","openid%20vo%20profile")
                        .withQueryStringParameter("state",state)
                        .withQueryStringParameter("nonce",nonce)
                //.withQueryStringParameter("acr_values","urn:be:vlaanderen:authmech:itsme%20urn:be:vlaanderen:authmech:eid%20urn:be:vlaanderen:authmech:csamtotp")
        ).respond(response().withStatusCode(200).withHeader(new Header(CONTENT_TYPE.toString(), "application/json"))
                .withBody("{\"code\":\"OV9FU_1lxJoAbc\",\"state\":\"" + state + "\"}"));

    }


    @Before
    public void startMockServer() {
        mockServer = startClientAndServer(1080);
        mockServer.when(request().withMethod("Post")
                        .withPath("/op/v1/token")
                .withBody("{client_id=28358814-5c20-4c13-bbff-db5dd8c4ae93&\n" +
                        "  client_secret=CgNjSBQwSolxUcFe7A0U-16j7uccp34-Z5eigKOoCpn5WMHjcb0IkseYA8zhMdYKlpzNJh4Qj4OhjvkVEXq6clvKlutFv5H&\n" +
                        "  code=OV9FU_1lxJoAbc&\n" +
                        "  grant_type=authorization_code&\n" +
                        "  redirect_uri=https%3A%2F%2Fmijntoepassing%2Fcallback}")
        ).respond(response().withStatusCode(200).withHeader(new Header(CONTENT_TYPE.toString(), "application/json"))
                .withBody("""
                        {"token_type": "Bearer",
                            "access_token": "-OYFUnq0TieWrbD5LOBsb2D3RdlsnCLDJ9nx11jHaCa",
                            "expires_in": 3600,
                            "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhY3IiOiJ1cm46YmU6dmxhYW5kZXJlbjphdXRobWVjaDpjc2FtdG90cCIsImF0X2hhc2giOiJGRTMxYlNSRThaMmQzcnVVTzFYczVBIiwiYXVkIjoiMjgzNTg4MTQtNWMyMC00YzEzLWJiZmYtZGI1ZGQ4YzRhZTkzIiwiYXpwIjoiMjgzNTg4MTQtNWMyMC00YzEzLWJiZmYtZGI1ZGQ4YzRhZTkzIiwiZXhwIjoxNTkzMDQ0MDMxLCJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKb2huIiwiaWF0IjoxNTkzMDM5MTY0LCJpc3MiOiJodHRwczovL2F1dGhlbnRpY2F0aWUudmxhYW5kZXJlbi5iZS9vcCIsImtpZCI6Il9GSVFFSWVhTFEzQVFNV3JxMDIyZ2gxN01IamtJWUhNV293R2o1THhIVG8iLCJub25jZSI6IkZKRWt6dWRuc2l6MzRremxEemw4MnB6b2QyMXNqc3k5MjJqZFNhcSIsInN1YiI6IjIzNjU2MjFkYjE1YzZlMjg0NmNhNzFhMWYyNzc0ZTc5ZmcyOGM0ODciLCJ2b19kb2VsZ3JvZXBjb2RlIjoiRUEiLCJ2b19pZCI6ImE1NzIwNzQ2LTRjOWUtNDhhOC05YWEwLTdhYjQ1NjY0ODQ4NyIsImp0aSI6ImUyN2EwYmJjLTBlNGMtNDhjMS04OTZhLWY5NWMwMzAwNjQ2ZiJ9.X13FbycIRJpQpJqBEBm_gHrvk-P9DkPB7-bc2KVqQ6Y"
                            }"""));
    }

    @Test
    public void DiscoveryTest() throws URISyntaxException, IOException, InterruptedException {
        Discovery discovery = new Discovery();
        assertEquals(discovery.getAuthorizationEndpoint(),"https://authenticatie-ti.vlaanderen.be/op/v1/auth");
    }

    @Test
    public void AuthorizationTest() throws URISyntaxException, IOException, InterruptedException {
        String state = getNewNonceState();
        String nonce = stateNonce.get(state);
        setAuthorizationResponse(state);
        var client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(new URI("http://localhost:1080/op/v1/auth?client_id=28358814-5c20-4c13-bbff-db5dd8c4ae93&state=" + state +"&nonce=" + nonce)).GET().header("accept", "application/json").build();
        var respons = client.send(request, HttpResponse.BodyHandlers.ofString());

        mockServer.verify(request().withPath("/op/v1/auth"), VerificationTimes.once());
        removeNonceState(state);
    }

    @Test
    public void TokenTest() throws URISyntaxException, IOException, InterruptedException {
        var client = HttpClient.newHttpClient();
        String requestBody = "{client_id=28358814-5c20-4c13-bbff-db5dd8c4ae93&\n" +
                "  client_secret=CgNjSBQwSolxUcFe7A0U-16j7uccp34-Z5eigKOoCpn5WMHjcb0IkseYA8zhMdYKlpzNJh4Qj4OhjvkVEXq6clvKlutFv5H&\n" +
                "  code=OV9FU_1lxJoAbc&\n" +
                "  grant_type=authorization_code&\n" +
                "  redirect_uri=https%3A%2F%2Fmijntoepassing%2Fcallback}";
        HttpRequest request = HttpRequest.newBuilder().uri(new URI("http://localhost:1080/op/v1/token")).POST(HttpRequest.BodyPublishers.ofString(requestBody)).header("accept", "application/json").build();
        var respons = client.send(request, HttpResponse.BodyHandlers.ofString());

        mockServer.verify(request().withPath("/op/v1/token"), VerificationTimes.once());
    }
    
    @Test
    public void AccessTokenTest() throws AuthenticationException, URISyntaxException, IOException, InterruptedException, java.text.ParseException, JOSEException {
        var token = new AccessToken("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhY3IiOiJ1cm46YmU6dmxhYW5kZXJlbjphdXRobWVjaDpjc2FtdG90cCIsImF0X2hhc2giOiJGRTMxYlNSRThaMmQzcnVVTzFYczVBIiwiYXVkIjoiMjgzNTg4MTQtNWMyMC00YzEzLWJiZmYtZGI1ZGQ4YzRhZTkzIiwiYXpwIjoiMjgzNTg4MTQtNWMyMC00YzEzLWJiZmYtZGI1ZGQ4YzRhZTkzIiwiZXhwIjoxNTkzMDQ0MDMxLCJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKb2huIiwiaWF0IjoxNTkzMDM5MTY0LCJpc3MiOiJodHRwczovL2F1dGhlbnRpY2F0aWUudmxhYW5kZXJlbi5iZS9vcCIsImtpZCI6Il9GSVFFSWVhTFEzQVFNV3JxMDIyZ2gxN01IamtJWUhNV293R2o1THhIVG8iLCJub25jZSI6IkZKRWt6dWRuc2l6MzRremxEemw4MnB6b2QyMXNqc3k5MjJqZFNhcSIsInN1YiI6IjIzNjU2MjFkYjE1YzZlMjg0NmNhNzFhMWYyNzc0ZTc5ZmcyOGM0ODciLCJ2b19kb2VsZ3JvZXBjb2RlIjoiRUEiLCJ2b19pZCI6ImE1NzIwNzQ2LTRjOWUtNDhhOC05YWEwLTdhYjQ1NjY0ODQ4NyIsImp0aSI6ImUyN2EwYmJjLTBlNGMtNDhjMS04OTZhLWY5NWMwMzAwNjQ2ZiJ9.X13FbycIRJpQpJqBEBm_gHrvk-P9DkPB7-bc2KVqQ6Y");
        token.validateToken();
        assertEquals(token.getValidationErrors(),"");
    }

    @Test
    public void completeLoginFlow() throws URISyntaxException, IOException, InterruptedException, AuthenticationException, ParseException, JOSEException {
        //Authentication Request
        var stateSend = getNewNonceState();
        setAuthorizationResponse(stateSend);
        var client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(new URI("http://localhost:1080/op/v1/auth?client_id=28358814-5c20-4c13-bbff-db5dd8c4ae93&state=" + stateSend +"&nonce=" + stateNonce.get(stateSend))).GET().header("accept", "application/json").build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());

        mockServer.verify(request().withPath("/op/v1/auth"), VerificationTimes.once());

        System.err.println("1. Authentication request received and successful. Following callback received:\n"+response.body());
        JSONObject jsonAuthorization = (JSONObject) JSONValue.parse(response.body());
        String code = (String) jsonAuthorization.get("code");
        String state = (String) jsonAuthorization.get("state");

        //Receive Token at Token Endpoint
        String requestBody = "{client_id=28358814-5c20-4c13-bbff-db5dd8c4ae93&\n" +
                "  client_secret=CgNjSBQwSolxUcFe7A0U-16j7uccp34-Z5eigKOoCpn5WMHjcb0IkseYA8zhMdYKlpzNJh4Qj4OhjvkVEXq6clvKlutFv5H&\n" +
                "  code="+code+"&\n" +
                "  grant_type=authorization_code&\n" +
                "  redirect_uri=https%3A%2F%2Fmijntoepassing%2Fcallback}";
        HttpRequest request2 = HttpRequest.newBuilder().uri(new URI("http://localhost:1080/op/v1/token")).POST(HttpRequest.BodyPublishers.ofString(requestBody)).header("accept", "application/json").build();
        var response2 = client.send(request2, HttpResponse.BodyHandlers.ofString());

        mockServer.verify(request().withPath("/op/v1/token"), VerificationTimes.once());

        System.err.println("2. Token request received. Following response received:\n" + response2.body());
        JSONObject jsonToken = (JSONObject) JSONValue.parse(response2.body());
        String idToken = (String) jsonToken.get("id_token");

        //Validate Token
        var token = new AccessToken(idToken);
        token.validateToken(stateNonce.get(state));
        if(token.getValidationErrors().isEmpty()){
            System.err.println("3. Token is valid");
        }else{
            System.err.println("3. Token validated: token is not valid with following errors:\n"+token.getValidationErrors());
        }

    }

    @After
    public void stopMockServer() {
        mockServer.stop();
    }
}
