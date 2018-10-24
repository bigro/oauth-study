package com.example.oauthstudy.login;

import com.google.common.net.UrlEscapers;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import static com.google.common.base.Preconditions.checkNotNull;

@Controller
public class LoginController {
    @Value("${client.id}")
    private String clientId;

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
}
