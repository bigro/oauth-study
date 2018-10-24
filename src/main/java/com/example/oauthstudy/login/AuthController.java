package com.example.oauthstudy.login;

import com.google.common.base.Splitter;
import com.google.common.net.UrlEscapers;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

import static com.example.oauthstudy.login.Utils.*;
import static com.google.api.client.repackaged.com.google.common.base.Preconditions.checkState;
import static com.google.common.base.Preconditions.checkNotNull;

@Controller
public class AuthController {
    @Value("${client.id}")
    private String clientId;

    @Value("${client.secret}")
    private String clientSecret;

    @GetMapping("/login")
    public String login(Model model) {

        String endpoint = "https://accounts.google.com/o/oauth2/v2/auth?"
                + "client_id=" + clientId + "&"
                + "redirect_uri="
                + UrlEscapers.urlFormParameterEscaper().escape("http://localhost:8080/auth")
                + "&"
                + "access_type=" + "online" + "&"
                + "state=" + "test_state" + "&"
                + "response_type=" + "code" + "&"
                + "scope="
                + UrlEscapers.urlFormParameterEscaper().escape("email profile");
        model.addAttribute("endpoint", endpoint);
        return "login";
    }

    @GetMapping("/auth")
    public String auth(HttpServletRequest request, Model model) throws IOException {
        Map<String, String> params = parseQueryParams(request);
        checkState(Objects.equals(params.get("state"), "test_state"));
        String code = URLDecoder.decode(checkNotNull(params.get("code")), StandardCharsets.UTF_8.toString());

        HashMap<String, String> map = new HashMap<>();
        map.put("code", code);
        map.put("client_id", clientId);
        map.put("client_secret", clientSecret);
        map.put("redirect_uri", "http://localhost:8080/auth");
        map.put("grant_type", "authorization_code");

        String response = httpPost("https://www.googleapis.com/oauth2/v4/token", map).parseAsString();
        Map<String, String> responseAsMap = parseJson(response);
        Map<String, String> id = parseIdToken(responseAsMap.get("id_token"));

        model.addAttribute("email", id.get("email"))
                .addAttribute("name", id.get("name"))
                .addAttribute("picture", id.get("picture"))
                .addAttribute("back", "/login");

        return "result";
    }

    private Map<String, String> parseIdToken(String idToken) throws IOException {

        List<String> idTokenList = Splitter.on(".").splitToList(idToken);

        Map<String, String> header = parseJson(base64ToStr(idTokenList.get(0)));
        Map<String, String> body = parseJson(base64ToStr(idTokenList.get(1)));
        String sign = idTokenList.get(2);

        Keys.Key key = retrieveKey(header.get("kid"));
        boolean result = verify(idTokenList.get(0) + "." + idTokenList.get(1), sign, key.n, key.e);
        checkState(result);
        HashSet<String> hashSet = new HashSet<>();
        hashSet.add("https://accounts.google.com");
        hashSet.add("accounts.google.com");
        checkState(hashSet.contains(body.get("iss")));
        checkState(Objects.equals(body.get("aud"), clientId));
        long now = System.currentTimeMillis();
        checkState(now <= Long.parseLong(body.get("exp")) * 1000 + 1000);
        checkState(now >= Long.parseLong(body.get("iat")) * 1000 - 1000);

        return body;
    }

    private static boolean verify(String contentToVerify, String sign, String n, String e) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                    new BigInteger(1, base64ToByte(n)),
                    new BigInteger(1, base64ToByte(e))
            )));
            signature.update(contentToVerify.getBytes(StandardCharsets.UTF_8));
            return signature.verify(base64ToByte(sign));

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static Keys.Key retrieveKey(String kid) throws IOException {

        String response = httpGet("https://accounts.google.com/.well-known/openid-configuration").parseAsString();
        Map<String, Object> responseAsMap = parseNestedJson(response);

        String jwks = responseAsMap.get("jwks_uri").toString();
        String keyResponse = httpGet(jwks).parseAsString();
        Keys keysResponseObj = parseJsonAs(keyResponse, Keys.class);
        return keysResponseObj.keys.stream()
                .filter(k -> k.kid.equals(kid))
                .findAny()
                .orElseThrow(IOException::new);
    }

    @SuppressWarnings({"unused", "MismatchedQueryAndUpdateOfCollection"})
    private static final class Keys {

        private static final class Key {
            private String kty;
            private String alg;
            private String use;
            private String kid;
            private String n;
            private String e;
        }

        private List<Key> keys;
    }

}
