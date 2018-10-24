package com.example.oauthstudy.login;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@SuppressWarnings("SameParameterValue")
final class Utils {

    private static final Gson gson = new Gson();
    static final GsonFactory gsonFactory = new GsonFactory();
    static final HttpTransport httpTransport = new NetHttpTransport();
    private static final Splitter.MapSplitter queryParamSplitter = Splitter.on("&")
            .withKeyValueSeparator("=");

    static byte[] base64ToByte(String source) {
        return BaseEncoding.base64Url().decode(source);
    }

    static String base64ToStr(String source) {
        return new String(BaseEncoding.base64Url().decode(source), StandardCharsets.UTF_8);
    }

    static Map<String, String> parseJson(String json) {
        return gson.fromJson(
                json,
                new TypeToken<Map<String, String>>() {
                }.getType()
        );
    }

    static <T> T parseJsonAs(String json, Class<T> cls) {
        return gson.fromJson(json, cls);
    }

    static Map<String, Object> parseNestedJson(String json) {
        return gson.fromJson(
                json,
                new TypeToken<Map<String, Object>>() {
                }.getType()
        );
    }

    static Map<String, String> parseQueryParams(HttpServletRequest request) {
        return queryParamSplitter.split(request.getQueryString());
    }

    static HttpResponse httpGet(String url) throws IOException {
        return httpTransport
                .createRequestFactory()
                .buildGetRequest(new GenericUrl(url))
                .execute();
    }

    static HttpResponse httpPost(String url, Map<String, String> params) throws IOException {
        return httpTransport
                .createRequestFactory()
                .buildPostRequest(
                        new GenericUrl(url),
                        new UrlEncodedContent(params)
                )
                .execute();
    }
}