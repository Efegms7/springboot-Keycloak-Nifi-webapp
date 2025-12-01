package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RegisterController {

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;
    @Value("${keycloak.realm}")
    private String realm;
    @Value("${keycloak.client-id}")
    private String clientId;

    @GetMapping("/register")
    public String registerForm() {
        // Keycloak'ın kendi kayıt sayfasına yönlendir
        String redirectUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/registrations" +
                "?client_id=" + clientId +
                "&response_type=code" +
                "&scope=openid" +
                "&redirect_uri=http://localhost:8080/keycloak-callback";
        return "redirect:" + redirectUrl;
    }
} 