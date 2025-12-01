package com.example.demo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
public class KeycloakAuthService {
    
    private static final Logger logger = LoggerFactory.getLogger(KeycloakAuthService.class);
    
    @Value("${keycloak.auth-server-url}")
    private String serverUrl;
    
    @Value("${keycloak.realm}")
    private String realm;
    
    @Value("${keycloak.client-id}")
    private String clientId;
    
    @Value("${keycloak.client-secret}")
    private String clientSecret;
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    // ========================================
    // 🏗️ CACHE KEY'LERİ
    // ========================================
    
    private static final String RESOURCES_CACHE = "keycloak_resources";
    private static final String POLICIES_CACHE = "keycloak_policies";
    private static final String SCOPES_CACHE = "keycloak_scopes";
    private static final String PERMISSIONS_CACHE = "keycloak_permissions";
    private static final String ROLES_CACHE = "keycloak_roles";
    private static final String CLIENTS_CACHE = "keycloak_clients";
    
    // ========================================
    // 🔑 TEMEL KEYCLOAK İŞLEMLERİ
    // ========================================
    
    /**
     * Authorization code'u token ile değiştirir
     * Kullanıcı tarayıcıda:
     * - Username/Password girer
     * - Keycloak'ta kimlik doğrulaması yapılır
     * - Başarılı olursa "authorization code" alınır
     * exchangeCodeForToken() method'u:
     * - Login sonrası gelen "code"u alır
     * - Bu "code"u "access token"a çevirir
     * "Sistemde ne var?" sorusunu cevaplar
     * Authorization Code: Kullanıcı girişi gerekir,Kullanıcı adına işlem,Kullanıcı bilgileri alınır
     * Client Credentials: Kullanıcı girişi olmadan,Uygulama kendi kimliği ile,Keycloak'tan admin yetkisi alınır
     */
    public Map<String, Object> exchangeCodeForToken(String code, String redirectUri) {
        try {
            logger.info("Authorization code token ile değiştiriliyor");
            
            String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "authorization_code");
            body.add("client_id", clientId);
            if (clientSecret != null && !clientSecret.isEmpty()) {
                body.add("client_secret", clientSecret);
            }
            body.add("code", code);
            body.add("redirect_uri", redirectUri);
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> tokenResponse = response.getBody();
                if (tokenResponse.containsKey("access_token")) {
                    String accessToken = (String) tokenResponse.get("access_token");
                    logger.info("Token başarıyla alındı");
                    return tokenResponse;
                }
            }
            return null;
        } catch (Exception e) {
            logger.error("Token değiştirme hatası: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Client credentials ile admin token alır
     * "Bu kullanıcı ne yapabilir?" sorusunu cevaplar
     * Kullanıcı girişi olmadan
     * Uygulama kendi kimliği ile
     * Keycloak'tan admin yetkisi alıyor
     */
    public String getClientCredentialsToken() {
        try {
            String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "client_credentials");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> tokenResponse = response.getBody();
                if (tokenResponse.containsKey("access_token")) {
                    String accessToken = (String) tokenResponse.get("access_token");
                    logger.info("Client credentials token alındı");
                    return accessToken;
                }
            }
            return null;
        } catch (Exception e) {
            logger.error("Client credentials token alma hatası: {}", e.getMessage());
            return null;
        }
    }
    
    // ========================================
    // 🏗️ KEYCLOAK ADMIN REST API - RESOURCES
    // ========================================
    
    /**
     * Keycloak'tan tüm resources'ları çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource
     * // Keycloak'ta tanımlı tüm resource'ları listeler
     * Resource: API endpoint'leri, sayfalar, dosyalar gibi
     * Hangi kaynakların korunduğunu gösterir
     */
    @Cacheable(value = RESOURCES_CACHE, key = "'all'")
    public List<Map<String, Object>> getResources() {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) {
                logger.error("Admin token alınamadı");
                return new ArrayList<>();
            }
            
            // Önce client UUID'yi al
            String clientUuid = getClientUuid();
            if (clientUuid == null) {
                logger.error("Client UUID alınamadı");
                return new ArrayList<>();
            }
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/resource", 
                serverUrl, realm, clientUuid);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<Map<String, Object>> resources = response.getBody();
                logger.info("{} resource başarıyla alındı", resources.size());
                
                // 🔍 DETAYLI RESOURCE LOG'LARI
                logger.info("=== KEYCLOAK RESOURCES DETAYI ===");
                for (int i = 0; i < resources.size(); i++) {
                    Map<String, Object> resource = resources.get(i);
                    logger.info("Resource {}: ID={}, Name={}, DisplayName={}, Type={}, URIs={}", 
                        i + 1,
                        resource.get("_id"),
                        resource.get("name"),
                        resource.get("displayName"),
                        resource.get("type"),
                        resource.get("uris"));
                }
                logger.info("=== RESOURCES DETAYI SONU ===");
                
                return resources;
            }
            
            return new ArrayList<>();
        } catch (Exception e) {
            logger.error("Resources çekme hatası: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * Belirli bir resource'ı ID ile çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}
     * Keycloak'ta belirli bir resource'ı
     * ID'si ile bulup detaylarını getiriyor
     * Tek bir resource hakkında detaylı bilgi alıyor
     */
    public Map<String, Object> getResourceById(String resourceId) {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new HashMap<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new HashMap<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/resource/%s", 
                serverUrl, realm, clientUuid, resourceId);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            
            return new HashMap<>();
        } catch (Exception e) {
            logger.error("Resource çekme hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    // ========================================
    // 🎯 KEYCLOAK ADMIN REST API - SCOPES
    // ========================================
    
    /**
     * Keycloak'tan tüm scopes'ları çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope
     * Keycloak'ta tanımlı tüm scope'ları listeler
     * Scope: okuma, yazma, silme gibi yetki türleri
     * Hangi işlemlerin yapılabileceğini gösterir
     */
    @Cacheable(value = SCOPES_CACHE, key = "'all'")
    public List<Map<String, Object>> getScopes() {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new ArrayList<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new ArrayList<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/scope", 
                serverUrl, realm, clientUuid);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<Map<String, Object>> scopes = response.getBody();
                logger.info("{} scope başarıyla alındı", scopes.size());
                
                // 🔍 DETAYLI SCOPE LOG'LARI
                logger.info("=== KEYCLOAK SCOPES DETAYI ===");
                for (int i = 0; i < scopes.size(); i++) {
                    Map<String, Object> scope = scopes.get(i);
                    logger.info("Scope {}: ID={}, Name={}, DisplayName={}, IconURI={}", 
                        i + 1,
                        scope.get("id"),
                        scope.get("name"),
                        scope.get("displayName"),
                        scope.get("iconUri"));
                }
                logger.info("=== SCOPES DETAYI SONU ===");
                
                return scopes;
            }
            
            return new ArrayList<>();
        } catch (Exception e) {
            logger.error("Scopes çekme hatası: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * Belirli bir scope'u ID ile çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}
     * Keycloak'ta belirli bir scope'ı
     * ID'si ile bulup detaylarını getiriyor
     * Tek bir scope hakkında detaylı bilgi alıyor
     */
    public Map<String, Object> getScopeById(String scopeId) {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new HashMap<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new HashMap<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/scope/%s", 
                serverUrl, realm, clientUuid, scopeId);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            
            return new HashMap<>();
        } catch (Exception e) {
            logger.error("Scope çekme hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    // ========================================
    // 🛡️ KEYCLOAK ADMIN REST API - POLICIES
    // ========================================
    
    /**
     * Keycloak'tan tüm policies'leri çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy
     * Keycloak'ta tanımlı tüm policy'leri listeler
     * Policy: Kim, neyi, ne zaman yapabilir kuralları
     * Güvenlik kurallarını gösterir
     */
    @Cacheable(value = POLICIES_CACHE, key = "'all'")
    public List<Map<String, Object>> getPolicies() {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new ArrayList<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new ArrayList<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/policy", 
                serverUrl, realm, clientUuid);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<Map<String, Object>> policies = response.getBody();
                logger.info("{} policy başarıyla alındı", policies.size());
                
                // 🔍 DETAYLI POLICY LOG'LARI
                logger.info("=== KEYCLOAK POLICIES DETAYI ===");
                for (int i = 0; i < policies.size(); i++) {
                    Map<String, Object> policy = policies.get(i);
                    logger.info("Policy {}: ID={}, Name={}, Type={}, Logic={}, DecisionStrategy={}", 
                        i + 1,
                        policy.get("id"),
                        policy.get("name"),
                        policy.get("type"),
                        policy.get("logic"),
                        policy.get("decisionStrategy"));
                }
                logger.info("=== POLICIES DETAYI SONU ===");
                
                return policies;
            }
            
            return new ArrayList<>();
        } catch (Exception e) {
            logger.error("Policies çekme hatası: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * Belirli bir policy'yi ID ile çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/{policy-id}
     * Keycloak'ta belirli bir policy'yi
     * ID'si ile bulup detaylarını getiriyor
     * Tek bir policy hakkında detaylı bilgi alıyor
     */
    public Map<String, Object> getPolicyById(String policyId) {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new HashMap<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new HashMap<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/policy/%s", 
                serverUrl, realm, clientUuid, policyId);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            
            return new HashMap<>();
        } catch (Exception e) {
            logger.error("Policy çekme hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    // ========================================
    // 👥 KEYCLOAK ADMIN REST API - ROLES
    // ========================================
    
    /**
     * Client roles'ları çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/roles
     * Keycloak'ta tanımlı tüm client role'ları listeler
     * Client role: Uygulamaya özel roller
     * Hangi rollerin tanımlandığını gösterir
     */
    @Cacheable(value = ROLES_CACHE, key = "'client'")
    public List<Map<String, Object>> getClientRoles() {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new ArrayList<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new ArrayList<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/roles", 
                serverUrl, realm, clientUuid);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<Map<String, Object>> roles = response.getBody();
                logger.info("{} client role başarıyla alındı", roles.size());
                
                // 🔍 DETAYLI CLIENT ROLE LOG'LARI
                logger.info("=== KEYCLOAK CLIENT ROLES DETAYI ===");
                for (int i = 0; i < roles.size(); i++) {
                    Map<String, Object> role = roles.get(i);
                    logger.info("Client Role {}: ID={}, Name={}, Description={}, Composite={}, ClientRole={}", 
                        i + 1,
                        role.get("id"),
                        role.get("name"),
                        role.get("description"),
                        role.get("composite"),
                        role.get("clientRole"));
                }
                logger.info("=== CLIENT ROLES DETAYI SONU ===");
                
                return roles;
            }
            
            return new ArrayList<>();
        } catch (Exception e) {
            logger.error("Client roles çekme hatası: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * Realm roles'ları çeker
     * Endpoint: GET /admin/realms/{realm}/roles
     * Keycloak'ta tanımlı tüm realm role'ları listeler
     * Realm role: Tüm realm'de geçerli roller
     * Hangi rollerin tanımlandığını gösterir
     */
    @Cacheable(value = ROLES_CACHE, key = "'realm'")
    public List<Map<String, Object>> getRealmRoles() {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new ArrayList<>();
            
            String url = String.format("%s/admin/realms/%s/roles", serverUrl, realm);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<Map<String, Object>> roles = response.getBody();
                logger.info("{} realm role başarıyla alındı", roles.size());
                
                // 🔍 DETAYLI REALM ROLE LOG'LARI
                logger.info("=== KEYCLOAK REALM ROLES DETAYI ===");
                for (int i = 0; i < roles.size(); i++) {
                    Map<String, Object> role = roles.get(i);
                    logger.info("Realm Role {}: ID={}, Name={}, Description={}, Composite={}, ClientRole={}", 
                        i + 1,
                        role.get("id"),
                        role.get("name"),
                        role.get("description"),
                        role.get("composite"),
                        role.get("clientRole"));
                }
                logger.info("=== REALM ROLES DETAYI SONU ===");
                
                return roles;
            }
            
            return new ArrayList<>();
        } catch (Exception e) {
            logger.error("Realm roles çekme hatası: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * Belirli bir role'u name ile çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}
     */
    public Map<String, Object> getClientRoleByName(String roleName) {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new HashMap<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new HashMap<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/roles/%s", 
                serverUrl, realm, clientUuid, roleName);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            
            return new HashMap<>();
        } catch (Exception e) {
            logger.error("Client role çekme hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    // ========================================
    // 🔧 UTILITY METHODS
    // ========================================
    
    /**
     * Client ID'den Client UUID'yi alır
     * Endpoint: GET /admin/realms/{realm}/clients?clientId={clientId}
     */
    @Cacheable(value = CLIENTS_CACHE, key = "'uuid'")
    public String getClientUuid() {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return null;
            
            String url = String.format("%s/admin/realms/%s/clients?clientId=%s", 
                serverUrl, realm, clientId);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<Map<String, Object>> clients = response.getBody();
                if (!clients.isEmpty()) {
                    Map<String, Object> client = clients.get(0);
                    String uuid = (String) client.get("id");
                    logger.info("Client UUID alındı: {}", uuid);
                    return uuid;
                }
            }
            
            return null;
        } catch (Exception e) {
            logger.error("Client UUID alma hatası: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * JWT token'dan user permissions çıkarır
     * JWT token'ı parse eder
        Her client için ayrı ayrı roller bulur
        Client ID → Roller mapping'i yapar
        Sonuç: Hangi client'ta hangi yetkiler var
     */
    public Map<String, Object> getUserPermissionsFromToken(String accessToken) {
        try {
            Map<String, Object> permissions = new HashMap<>();
            Map<String, Object> tokenInfo = getTokenInfo(accessToken);
            
            // Extract permissions from resource_access
            if (tokenInfo.containsKey("resource_access")) {
                Map<String, Object> resourceAccess = (Map<String, Object>) tokenInfo.get("resource_access");
                
                for (String clientId : resourceAccess.keySet()) {
                    Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
                    if (clientAccess.containsKey("roles")) {
                        List<String> roles = (List<String>) clientAccess.get("roles");
                        Set<String> scopes = new HashSet<>(roles);
                        permissions.put(clientId, scopes);
                    }
                }
            }
            
            // Extract permissions from realm_access
            if (tokenInfo.containsKey("realm_access")) {
                Map<String, Object> realmAccess = (Map<String, Object>) tokenInfo.get("realm_access");
                if (realmAccess.containsKey("roles")) {
                    List<String> realmRoles = (List<String>) realmAccess.get("roles");
                    Set<String> scopes = new HashSet<>(realmRoles);
                    permissions.put("realm", scopes);
                }
            }
            
            return permissions;
        } catch (Exception e) {
            logger.error("Token'dan permission çıkarma hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * JWT token'dan user roles çıkarır
     * JWT token'dan kullanıcının tüm rollerini çıkarır
     * İşlem:
     * 1. Realm rollerini alır (realm_access.roles)
     * 2. Client rollerini alır (resource_access.client_id.roles)
     * 3. Tüm roller tek listede birleştirir
     */
    public List<String> getUserRoles(String accessToken) {
        try {
            Map<String, Object> tokenInfo = getTokenInfo(accessToken);
            List<String> roles = new ArrayList<>();
            
            // Check realm_access.roles
            if (tokenInfo.containsKey("realm_access")) {
                Map<String, Object> realmAccess = (Map<String, Object>) tokenInfo.get("realm_access");
                if (realmAccess.containsKey("roles")) {
                    List<String> realmRoles = (List<String>) realmAccess.get("roles");
                    roles.addAll(realmRoles);
                }
            }
            
            // Check resource_access.client_id.roles
            if (tokenInfo.containsKey("resource_access")) {
                Map<String, Object> resourceAccess = (Map<String, Object>) tokenInfo.get("resource_access");
                if (resourceAccess.containsKey(clientId)) {
                    Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
                    if (clientAccess.containsKey("roles")) {
                        List<String> clientRoles = (List<String>) clientAccess.get("roles");
                        roles.addAll(clientRoles);
                    }
                }
            }
            
            return roles;
        } catch (Exception e) {
            logger.error("Token'dan role çıkarma hatası: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * JWT token'dan bilgi çıkarır
     */
    private Map<String, Object> getTokenInfo(String accessToken) {
        try {
            String[] parts = accessToken.split("\\.");
            if (parts.length != 3) return new HashMap<>();
            
            String payload = new String(Base64.getDecoder().decode(parts[1]));
            return objectMapper.readValue(payload, Map.class);
        } catch (Exception e) {
            logger.error("Token parse hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * Permission kontrolü yapar
     * Kullanıcının belirli bir resource ve scope'a yetkisi olup olmadığını kontrol eder
     * İşlem:
     * 1. JWT token'dan kullanıcı permission'larını alır
     * 2. Belirtilen resource'da scope var mı kontrol eder
     * 3. Set veya List formatında arama yapar
     */
    public boolean hasPermission(String accessToken, String resource, String scope) {
        try {
            Map<String, Object> userPermissions = getUserPermissionsFromToken(accessToken);
            
            if (userPermissions.containsKey(resource)) {
                Object resourceValue = userPermissions.get(resource);
                if (resourceValue instanceof Set) {
                    Set<String> resourceScopes = (Set<String>) resourceValue;
                    return resourceScopes.contains(scope);
                } else if (resourceValue instanceof List) {
                    List<?> resourceList = (List<?>) resourceValue;
                    return resourceList.stream().anyMatch(item -> scope.equals(item.toString()));
                }
            }
            
            return false;
        } catch (Exception e) {
            logger.error("Permission kontrolü hatası: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Tüm user permissions'ları çeker
     * Kullanıcının tüm permission'larını düzenli formatta döndürür
     * İşlem:
     * 1. Raw permission'ları alır (List, Set, String karışık)
     * 2. Hepsini Set<String> formatına çevirir
     * 3. Tutarlı format sağlar
     */
    public Map<String, Set<String>> getAllUserPermissions(String accessToken) {
        Map<String, Object> rawPermissions = getUserPermissionsFromToken(accessToken);
        Map<String, Set<String>> formattedPermissions = new HashMap<>();
        
        // Convert Map<String, Object> to Map<String, Set<String>>
        for (Map.Entry<String, Object> entry : rawPermissions.entrySet()) {
            if (entry.getValue() instanceof List) {
                List<?> list = (List<?>) entry.getValue();
                Set<String> stringSet = list.stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet());
                formattedPermissions.put(entry.getKey(), stringSet);
            } else if (entry.getValue() instanceof Set) {
                Set<?> set = (Set<?>) entry.getValue();
                Set<String> stringSet = set.stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet());
                formattedPermissions.put(entry.getKey(), stringSet);
            } else {
                Set<String> singleValue = new HashSet<>();
                singleValue.add(entry.getValue().toString());
                formattedPermissions.put(entry.getKey(), singleValue);
            }
        }
        
        return formattedPermissions;
    }
    
    // ========================================
    // 🔄 CACHE MANAGEMENT
    // ========================================
    
    @Scheduled(fixedRate = 30, timeUnit = TimeUnit.MINUTES)
    public void evictCaches() {
        logger.info("Keycloak cache'leri temizleniyor...");
    }
    
    @CacheEvict(value = {RESOURCES_CACHE, POLICIES_CACHE, SCOPES_CACHE, ROLES_CACHE, CLIENTS_CACHE}, allEntries = true)
    public void clearAllCaches() {
        logger.info("Tüm Keycloak cache'leri temizlendi");
    }
    
    // ========================================
    // 📊 COMPREHENSIVE ANALYSIS
    // ========================================
    
    /**
     * Tüm permissions'ları analiz eder
     */
    public Map<String, Object> analyzeAllPermissions(String accessToken) {
        try {
            Map<String, Object> analysis = new HashMap<>();
            
            // Get JWT token permissions
            Map<String, Object> jwtPermissions = getUserPermissionsFromToken(accessToken);
            analysis.put("jwtPermissions", jwtPermissions);
            analysis.put("jwtPermissionsCount", jwtPermissions.size());
            
            // Get Keycloak resources
            List<Map<String, Object>> resources = getResources();
            analysis.put("resources", resources);
            analysis.put("resourcesCount", resources.size());
            
            // Get Keycloak scopes
            List<Map<String, Object>> scopes = getScopes();
            analysis.put("scopes", scopes);
            analysis.put("scopesCount", scopes.size());
            
            // Get Keycloak policies
            List<Map<String, Object>> policies = getPolicies();
            analysis.put("policies", policies);
            analysis.put("policiesCount", policies.size());
            
            // Get Keycloak roles
            List<Map<String, Object>> clientRoles = getClientRoles();
            List<Map<String, Object>> realmRoles = getRealmRoles();
            analysis.put("clientRoles", clientRoles);
            analysis.put("realmRoles", realmRoles);
            analysis.put("totalRolesCount", clientRoles.size() + realmRoles.size());
            
            logger.info("Permission analizi tamamlandı: JWT={}, Resources={}, Scopes={}, Policies={}", 
                jwtPermissions.size(), resources.size(), scopes.size(), policies.size());
            
            return analysis;
        } catch (Exception e) {
            logger.error("Permission analizi hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * Permission özeti sağlar
     */
    public Map<String, Object> getPermissionSummary(String accessToken) {
        try {
            Map<String, Object> summary = new HashMap<>();
            
            Map<String, Object> allPermissions = analyzeAllPermissions(accessToken);
            summary.put("totalPermissions", allPermissions.get("jwtPermissionsCount"));
            summary.put("totalResources", allPermissions.get("resourcesCount"));
            summary.put("totalScopes", allPermissions.get("scopesCount"));
            summary.put("totalPolicies", allPermissions.get("policiesCount"));
            summary.put("totalRoles", allPermissions.get("totalRolesCount"));
            
            // User info
            Map<String, Object> tokenInfo = getTokenInfo(accessToken);
            summary.put("username", tokenInfo.get("preferred_username"));
            summary.put("email", tokenInfo.get("email"));
            summary.put("fullName", tokenInfo.get("name"));
            
            logger.info("Permission özeti alındı: User={}, Permissions={}, Resources={}, Scopes={}", 
                summary.get("username"), summary.get("totalPermissions"), 
                summary.get("totalResources"), summary.get("totalScopes"));
            
            return summary;
        } catch (Exception e) {
            logger.error("Permission özeti hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * Otomatik permission kontrolü yapar
     */
    public Map<String, Object> checkAllPermissionsAutomatically(String accessToken) {
        try {
            logger.info("Otomatik permission kontrolü başlatılıyor...");
            
            // Analyze all permissions
            Map<String, Object> allPermissions = analyzeAllPermissions(accessToken);
            
            // Get permission summary
            Map<String, Object> summary = getPermissionSummary(accessToken);
            
            // Get role hierarchy
            Map<String, Object> roleHierarchy = analyzeRoleHierarchy();
            
            // Get role permissions mapping
            Map<String, Object> rolePermissions = mapRolePermissions();
            
            // Get Keycloak statistics
            Map<String, Object> statistics = getKeycloakStatistics();
            
            // Combine all results
            Map<String, Object> results = new HashMap<>();
            results.put("allPermissionResults", allPermissions);
            results.put("permissionSummary", summary);
            results.put("roleHierarchy", roleHierarchy);
            results.put("rolePermissions", rolePermissions);
            results.put("keycloakStatistics", statistics);
            
            logger.info("Otomatik permission kontrolü tamamlandı: {} permission, {} resource, {} scope", 
                summary.get("totalPermissions"), summary.get("totalResources"), summary.get("totalScopes"));
            
            return results;
        } catch (Exception e) {
            logger.error("Otomatik permission kontrolü hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * Role hierarchy analizi yapar
     */
    private Map<String, Object> analyzeRoleHierarchy() {
        try {
            Map<String, Object> hierarchy = new HashMap<>();
            
            List<Map<String, Object>> realmRoles = getRealmRoles();
            List<Map<String, Object>> clientRoles = getClientRoles();
            
            hierarchy.put("realmRoles", realmRoles);
            hierarchy.put("clientRoles", clientRoles);
            hierarchy.put("totalRoles", realmRoles.size() + clientRoles.size());
            
            return hierarchy;
        } catch (Exception e) {
            logger.error("Role hierarchy analizi hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * Role permissions mapping yapar
     */
    private Map<String, Object> mapRolePermissions() {
        try {
            Map<String, Object> mapping = new HashMap<>();
            
            List<Map<String, Object>> policies = getPolicies();
            List<Map<String, Object>> resources = getResources();
            List<Map<String, Object>> scopes = getScopes();
            List<Map<String, Object>> permissions = getPermissions();
            
            mapping.put("policies", policies);
            mapping.put("resources", resources);
            mapping.put("scopes", scopes);
            mapping.put("permissions", permissions);
            mapping.put("totalMappings", policies.size() + resources.size() + scopes.size() + permissions.size());
            
            return mapping;
        } catch (Exception e) {
            logger.error("Role permissions mapping hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * Keycloak istatistikleri sağlar
     */
    private Map<String, Object> getKeycloakStatistics() {
        try {
            Map<String, Object> stats = new HashMap<>();
            
            List<Map<String, Object>> resources = getResources();
            List<Map<String, Object>> scopes = getScopes();
            List<Map<String, Object>> policies = getPolicies();
            List<Map<String, Object>> permissions = getPermissions();
            List<Map<String, Object>> realmRoles = getRealmRoles();
            List<Map<String, Object>> clientRoles = getClientRoles();
            
            stats.put("totalResources", resources.size());
            stats.put("totalScopes", scopes.size());
            stats.put("totalPolicies", policies.size());
            stats.put("totalPermissions", permissions.size());
            stats.put("totalRealmRoles", realmRoles.size());
            stats.put("totalClientRoles", clientRoles.size());
            stats.put("totalRoles", realmRoles.size() + clientRoles.size());
            
            return stats;
        } catch (Exception e) {
            logger.error("Keycloak istatistikleri hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * JWT token'dan user info çıkarır
     */
    public Map<String, Object> getUserInfoFromToken(String accessToken) {
        try {
            Map<String, Object> tokenInfo = getTokenInfo(accessToken);
            Map<String, Object> userInfo = new HashMap<>();
            
            // Basic user info
            userInfo.put("sub", tokenInfo.get("sub"));
            userInfo.put("preferred_username", tokenInfo.get("preferred_username"));
            userInfo.put("email", tokenInfo.get("email"));
            userInfo.put("name", tokenInfo.get("name"));
            userInfo.put("given_name", tokenInfo.get("given_name"));
            userInfo.put("family_name", tokenInfo.get("family_name"));
            
            // Roles
            List<String> roles = getUserRoles(accessToken);
            userInfo.put("roles", roles);
            
            // Permissions
            Map<String, Object> permissions = getUserPermissionsFromToken(accessToken);
            userInfo.put("permissions", permissions);
            
            logger.info("User info alındı: {}", userInfo.get("preferred_username"));
            return userInfo;
        } catch (Exception e) {
            logger.error("User info alma hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
    /**
     * Keycloak'tan tüm permission'ları çeker
     * Endpoint: GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission
     */
    @Cacheable(value = PERMISSIONS_CACHE, key = "'all'")
    public List<Map<String, Object>> getPermissions() {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) {
                logger.error("Admin token alınamadı");
                return new ArrayList<>();
            }
            
            // Önce client UUID'yi al
            String clientUuid = getClientUuid();
            if (clientUuid == null) {
                logger.error("Client UUID alınamadı");
                return new ArrayList<>();
            }
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/permission", 
                serverUrl, realm, clientUuid);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                List<Map<String, Object>> permissions = response.getBody();
                logger.info("{} permission başarıyla alındı", permissions.size());
                
                // 🔍 DETAYLI PERMISSION LOG'LARI
                logger.info("=== KEYCLOAK PERMISSIONS DETAYI ===");
                for (int i = 0; i < permissions.size(); i++) {
                    Map<String, Object> permission = permissions.get(i);
                    logger.info("Permission {}: ID={}, Name={}, Type={}, AssociatedPolicy={}, Description={}", 
                        i + 1,
                        permission.get("id"),
                        permission.get("name"),
                        permission.get("type"),
                        permission.get("associatedPolicy"),
                        permission.get("description"));
                }
                logger.info("=== PERMISSIONS DETAYI SONU ===");
                
                return permissions;
            }
            
            return new ArrayList<>();
        } catch (Exception e) {
            logger.error("Permissions çekme hatası: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * Belirli bir permission'ı ID ile getirir
     */
    public Map<String, Object> getPermissionById(String permissionId) {
        try {
            String adminToken = getClientCredentialsToken();
            if (adminToken == null) return new HashMap<>();
            
            String clientUuid = getClientUuid();
            if (clientUuid == null) return new HashMap<>();
            
            String url = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/permission/%s", 
                serverUrl, realm, clientUuid, permissionId);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            
            return new HashMap<>();
        } catch (Exception e) {
            logger.error("Permission çekme hatası: {}", e.getMessage());
            return new HashMap<>();
        }
    }
    
}
