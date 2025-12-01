package com.example.demo;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.ClientRequest;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;

import javax.net.ssl.SSLException;

@Configuration
public class NiFiClientConfig {

    @Value("${nifi.base-url}")
    private String nifiBaseUrl;

    private final NiFiTokenService tokenService;

    public NiFiClientConfig(NiFiTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Bean
    public WebClient nifiClient() throws SSLException {
        // 🔹 SSL doğrulamasını devre dışı bırak (test için)
        SslContext sslContext = SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        HttpClient httpClient = HttpClient.create()
                .secure(spec -> spec.sslContext(sslContext));

        return WebClient.builder()
                .baseUrl(nifiBaseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter((request, next) -> {
                    // Inject fresh token per request
                    String token = tokenService.getValidToken();
                    return next.exchange(
                            ClientRequest.from(request)
                                    .headers(h -> h.setBearerAuth(token))
                                    .headers(h -> h.add("X-Requested-By", "spring-client"))
                                    .build()
                    ).flatMap(response -> {
                        if (response.statusCode().value() == 401) {
                            // Refresh and retry once
                            String newToken = tokenService.refreshToken();
                            return next.exchange(
                                    ClientRequest.from(request)
                                            .headers(h -> h.setBearerAuth(newToken))
                                            .headers(h -> h.add("X-Requested-By", "spring-client"))
                                            .build()
                            );
                        }
                        return Mono.just(response);
                    });
                })
                .build();
    }
}