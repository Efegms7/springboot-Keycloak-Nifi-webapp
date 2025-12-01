package com.example.demo;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.http.client.HttpClient;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import javax.net.ssl.SSLException;

import java.time.Instant;
import java.time.Duration;
import java.util.Objects;

@Service
public class NiFiTokenService {

    private static final Logger logger = LoggerFactory.getLogger(NiFiTokenService.class);

    private WebClient tokenClient;

    private volatile String cachedToken;
    private volatile Instant tokenExpiresAt;

    @Value("${nifi.base-url}")
    private String nifiBaseUrl;

    @Value("${nifi.username}")
    private String username;

    @Value("${nifi.password}")
    private String password;

    @PostConstruct
    public void init() throws SSLException {
        // Accept self-signed certs for local/dev NiFi
        SslContext sslContext = SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
        HttpClient httpClient = HttpClient.create().secure(spec -> spec.sslContext(sslContext));

        this.tokenClient = WebClient.builder()
                .baseUrl(nifiBaseUrl.replace("/nifi-api", ""))
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    public synchronized String getValidToken() {
        if (cachedToken != null && tokenExpiresAt != null) {
            // Refresh slightly before actual expiry (30 seconds early)
            if (Instant.now().isBefore(tokenExpiresAt.minusSeconds(30))) {
                return cachedToken;
            }
        }
        return refreshToken();
    }

    public synchronized String refreshToken() {
        logger.info("Refreshing NiFi access token...");

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("username", Objects.requireNonNull(username, "nifi.username is required"));
        form.add("password", Objects.requireNonNull(password, "nifi.password is required"));

        String token = tokenClient.post()
                .uri("/nifi-api/access/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        if (token == null || token.isBlank()) {
            throw new IllegalStateException("Failed to retrieve NiFi token: empty response");
        }

        // NiFi token genelde kısa ömürlüdür; varsayılan 1 saat gibi düşünüp 55 dk cacheleyelim.
        this.cachedToken = token.trim();
        this.tokenExpiresAt = Instant.now().plus(Duration.ofMinutes(55));

        logger.info("NiFi access token acquired and cached.");
        return this.cachedToken;
    }
}


