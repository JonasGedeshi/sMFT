import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Discovery {
    private static final String TEST_URL = "https://authenticatie-ti.vlaanderen.be/op/.well-known/openid-configuration";
    private static final String PRODUCTION_URL = "https://authenticatie.vlaanderen.be/op/.well-known/openid-configuration";

    private JSONObject getURLs() throws URISyntaxException, InterruptedException, IOException {
        var client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(new URI(TEST_URL)).GET().header("accept", "application/json").build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String body = response.body();
        JSONObject jsonObject = (JSONObject) JSONValue.parse(body);
        return jsonObject;
    }

    public String getAuthorizationEndpoint() throws URISyntaxException, IOException, InterruptedException {
        return (String) getURLs().get("authorization_endpoint");
    }

    public String getEndSessionEndpoint() throws URISyntaxException, IOException, InterruptedException {
        return (String) getURLs().get("end_session_endpoint");
    }

    public String getJWKSURI() throws URISyntaxException, IOException, InterruptedException {
        return (String) getURLs().get("jwks_uri");
    }

    public String getTokenEndpoint() throws URISyntaxException, IOException, InterruptedException {
        return (String) getURLs().get("token_endpoint");
    }

}
