package com.example.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
@RequestMapping("/nifi")
public class NiFiController {

    private static final Logger logger = LoggerFactory.getLogger(NiFiController.class);

    private final WebClient client;
    private final String processGroupId = "28be6c08-27e2-39c6-a288-337a12d92418";

    public NiFiController(WebClient client) {
        this.client = client;
    }

    @PostMapping("/start")
    public String startFlow() {
        String body = String.format("""
            {
              "id": "%s",
              "state": "RUNNING",
              "disconnectedNodeAcknowledged": false
            }
            """, processGroupId);

        try {
            String response = client.put()
                    .uri("/flow/process-groups/" + processGroupId)
                    .header("Content-Type", "application/json")
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            logger.info("Flow başlatıldı. NiFi cevabı: {}", response != null ? response : "Body boş geldi");
            return "Flow başlatıldı ✅";
        } catch (Exception e) {
            logger.error("Flow başlatılamadı!", e);
            return "Flow başlatılamadı ❌";
        }
    }

    @PostMapping("/stop")
    public String stopFlow() {
        String body = String.format("""
            {
              "id": "%s",
              "state": "STOPPED",
              "disconnectedNodeAcknowledged": false
            }
            """, processGroupId);

        try {
            String response = client.put()
                    .uri("/flow/process-groups/" + processGroupId)
                    .header("Content-Type", "application/json")
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            logger.info("Flow durduruldu. NiFi cevabı: {}", response != null ? response : "Body boş geldi");
            return "Flow durduruldu ⛔";
        } catch (Exception e) {
            logger.error("Flow durdurulamadı!", e);
            return "Flow durdurulamadı ❌";
        }
    }
}