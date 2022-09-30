import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import shaded_package.com.nimbusds.jose.JOSEException;
import shaded_package.com.nimbusds.jose.jwk.JWK;
import shaded_package.com.nimbusds.jose.jwk.JWKSet;
import shaded_package.org.apache.http.auth.AuthenticationException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.util.Base64;

public class AccessToken {

    private String idToken;
    private JSONObject jsonHeader;
    private JSONObject jsonToken;
    private String signature;
    private String tokenWithoutSignature;
    private int issuedAtTime = 3000;

    private static String keys ="{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"Um2YQD5JJ9J8R0CI7dunPX19_fgvhE385o3CUF-lF3w\",\"kty\":\"RSA\",\"n\":\"zhaWQfkxfcoCrgQZTvbaOV_jd24fZWTWWdRXCbR6HvgYegL-fOczy7_8YwOoC8F2IizPDXpRlOfRQTWGe8rSxaSPWq1I8JTkn5q_2nhG9APGSTgJCjan4DuplQxQFiGrNvygkklX573juaMUHG5WvxXqIGZSyAvfmkse0ZL2zAxMTiggCwuoMw4dV4J-f782sh03jC8Oxs_7v39wOY3IYJldXX3PyXAVl7Te7fHG-OPdrvHuDUgLrQf8YrXqJeVsygcRPaxFX_Y6wsTSQUetJvzy23wslk07nV5f6Gm35uNGvaEy3o6Cgz0giH4zHDs1UeFrp4H_cNsMrSRC-ELgWQ\",\"use\":\"sig\"},{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"8RbhQkClLOvyIK_J2xPuWEgequer2WieZbbxKzhL21w\",\"kty\":\"RSA\",\"n\":\"3Bm_h0OCoLZjE-FAgkNLIVG-BPOnE0L9lU402QB8r7N_GiIaeAsNWlviU1kYfQykQuKPyksJQ0BPtP8D80AphyFPb0KUWzGi9TRiQjBHttPJmoFGjInyj2zS9c__9TC9SaewSYb1Wc_9xRs6nk5_hljtCFjiNnMj_Xa08CvXxlJif4HyYefk8t2c1FgMQM7dOYLBtbOuCUSQqTSOckNVxbx_3HmNSEPQyY4sdrWYfmBIhcgvWzvyBM4ZOQ3TsocjxI7N1bjV8bDOOpc_LGJ7HFbT1iglqiRLr5D7Z91bDC41nD5Gsg-Rj36ujWI2GCZyKhJMBXlYCkjNqLMTkrGBtw\",\"use\":\"sig\"},{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"VoK60dHxNhO5GEaFkGTCVLnouOkx3vLeRlBV7nCbAVc\",\"kty\":\"RSA\",\"n\":\"x7ABJ2HDwVd8MHE8D6dR_JBgDqvgl5fj__7bG48HwqIvV4fwSM8ufCt_IkMTkodU0R8zJNNNXHQvDsI8cjQykYFn0OoL9k61WarKDEeSUzCEHOOPRbbrfdr1bSKYur8qjBTb0x2C4GyBGOtj67gyu4_k_XBaSDMlFC-5fxbv2VmtksDDQ33k75LeOw_gtKmhQdDuMMCkIzV6VVsQlI_aT3Gq0DnaOxPkHFvxHLGTOLBbf5zTyUtpVMhgztl3oIJMMRe0I6T3DZ_XgC61NpBjWUyCqj2A7jYAnfnjEXYMrIewhqiB4MaXAkIQ5Lk2TO9TJaDNwsrWWRo0Kjb46OTuPw\",\"use\":\"sig\"},{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"E2QASw_eBdicdqqRE0WiRTH1ZS59OLGXyeemieo5G3k\",\"kty\":\"RSA\",\"n\":\"tC_BYWcmRisZDIWriU8pBviekCN8xTCrzb50QqCIO9CuZSiJJj8NiZ8y3vHLF6QGo6snC4MBcoeugX9VVXZhUTKx5st3BzH39YmbNefFvszt6VcMaJ1SqoBPi2WSqJCAvb4KvbyfBYA2RUfcLoDV-MKwmwWPoElJtMRjoiGBV3oEMH-7ildx84jsSzzCyVweNySl_b5mRqH-Tu4pzRsQg0SSpcBdBv0yljsFX-x5y5tN2u0_oI4UaTmFUTBnEDBwjBgkXJACb6nITVfRr9RgETnhqUrNt0eNejuwEMHhvgci4-wLlW_mqX8C9x6QHNm1QVhM7RnFE9FSixplYdl5Rw\",\"use\":\"sig\"},{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"-9KasXpzwMjnQ4zmtNvhH9-EAGvQaCZUo48seIYOAQg\",\"kty\":\"RSA\",\"n\":\"yHOFOowRBnRUjdn9oCC1Jp6Se2dbqQigCKBYWalfnPpw9iZR2J0MO4Tu7hPkep-gnQ6el3HjaXPGNavZt33UcoG5mmD0Gf8s_HBD0HqB-DGl5eiy_LaLcmLrbbKMvSE3qVI2911uUCWdFhz7l7frHo9WHVN191OAOVLs0Gq-p0VWxxbeT2BWpMRuef0ie4-E37wtGE7sEjw8o4Bx8Zw1OCAQoi05ATkdmlEZw6YVzvZNuEngYJswrQ5namRngPgujSLTD4PXY1cxu2G9Z9-MZQgJOuH9Nxk4x2iw1nxNfsXm5h35HYIF5J4AAWMqftY4DidFOip4mSpgdBrusBKoJw\",\"use\":\"sig\"},{\"alg\": \"RS256\",\"e\": \"AQAB\",\"kid\": \"lEFnQt-jonEX5JxR6T-z8eGzvJahW0ifmI5JXs8YoJs\",\"kty\": \"RSA\",\"n\": \"26BR4cUDdWmQ014XI356O5xEjmvli2AKs0A7710ij1D_TW4CKCGrG0_FLJ4EABQYfY2UQGObdTXq4_U8YFr_qW6a9Tj8Jp7iM-5sP4vkMKgeVf_Wr_3Sw_3Gp_fQjzlUyAfo5TLvQrKqqYU-LIwWZtPpdMiMEaCAruu29r_hKdiULBO_MgQF7cICiYUp4ERAqh4I0VrNkB8W6_0Z3JGpNp6TTQGtZ-TtMF3BLKE33G4ygduzHjooJ3ogasS2qmbKgMVUzcWNAsONwNc_lA0OJJeLCLY5RbR7ffUZtGDMTDBQFdK1C8mlxzIscfsNwC8w-1pB3fibmcNf2SEl9ssp7w\",\"use\": \"sig\"}]}";

    private static final String clientId = "28358814-5c20-4c13-bbff-db5dd8c4ae93";

    public AccessToken(String idToken){
        this.idToken = idToken;
        decodeToken(idToken);
    }

    private void decodeToken(String idToken){
        String[] chunks = idToken.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));
        //System.err.println(header);
        jsonHeader = (JSONObject) JSONValue.parse(header);
        jsonToken = (JSONObject) JSONValue.parse(payload);
        tokenWithoutSignature = header + "." + payload;
        signature = new String(decoder.decode(chunks[2]));
    }

    private void signatureValidation() throws java.text.ParseException, URISyntaxException, IOException, InterruptedException, JOSEException {
        JWKSet jwkSet = JWKSet.parse(keys);
        JWKSet publicKeys = JWKSet.load(new URL(new Discovery().getJWKSURI()));
        JWK jwk = publicKeys.getKeyByKeyId((String)jsonToken.get("kid"));
        jwk = jwkSet.getKeyByKeyId("lEFnQt-jonEX5JxR6T-z8eGzvJahW0ifmI5JXs8YoJs");
        var keyTest = jwk.toRSAKey().toRSAPublicKey();

        Algorithm algorithm = Algorithm.RSA256(keyTest,null);
        DecodedJWT jwt = JWT.decode(idToken);
        algorithm.verify(jwt);
    }

    public void validateToken() throws URISyntaxException, IOException, InterruptedException, AuthenticationException, java.text.ParseException, JOSEException {
        Discovery discovery = new Discovery("production");

        //signature validate
        //signatureValidation();

        //"iss"-claim is OpenId Connect Provider
        if(!(jsonToken.get("iss").equals(discovery.getIssuer()))) throw new AuthenticationException("issuer is not the OpenID Connect Provider");

        //ClientId = "aud"
        var aud = jsonToken.get("aud");
        if(aud instanceof String){
            if(!(aud.equals(clientId))) throw new AuthenticationException("ClientId is not the same as own ClientID");
        }
        else {
            if (((JSONArray) aud).contains(clientId)) throw new AuthenticationException("ClientId is not the same as own ClientID");
        }

        //expiry time
        //if((long) jsonToken.get("exp") < (System.currentTimeMillis()/1000)) throw new AuthenticationException("Expiry time is greater than current timestamp");

        //issued at not too long ago
        //if((long) jsonToken.get("iat") + issuedAtTime < (System.currentTimeMillis()/1000)) throw new AuthenticationException("Issued time is too long ago");

        //acr claim?
    }

    public void validateToken(String nonce) throws AuthenticationException, URISyntaxException, IOException, ParseException, InterruptedException, JOSEException {
        validateToken();

        //nonce
        if(jsonToken.get("nonce").equals(nonce))  throw new AuthenticationException("value of nonce is not the same as in Authentication Request");
    }

}
