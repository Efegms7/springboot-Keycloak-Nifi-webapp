package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.Map;
import java.util.List;
import java.util.Set;

@Controller
public class LoginController {
    @Autowired
    private KeycloakAuthService keycloakAuthService;
    
    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;
    
    @Value("${keycloak.realm}")
    private String realm;
    
    @Value("${keycloak.client-id}")
    private String clientId;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    
    @GetMapping("/keycloak-login")
    public String keycloakLogin() {
        // Keycloak authorization endpoint'ine yönlendir
        String redirectUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/auth" +
                           "?client_id=" + clientId +
                           "&response_type=code" +
                           "&scope=openid" +
                           "&redirect_uri=http://localhost:8080/keycloak-callback";
        
        return "redirect:" + redirectUrl;
    }
    
    @GetMapping("/keycloak-callback")
    public String keycloakCallback(@RequestParam(required = false) String code, 
                                 @RequestParam(required = false) String error,
                                 Model model, HttpSession session) {
        if (error != null) {
            model.addAttribute("error", "Keycloak hatası: " + error);
            return "login";
        }
        
        if (code == null) {
            model.addAttribute("error", "Authorization code alınamadı");
            return "login";
        }
        
        try {
            // Authorization code'u token ile değiştir
            String redirectUri = "http://localhost:8080/keycloak-callback";
            Map<String, Object> tokenResponse = keycloakAuthService.exchangeCodeForToken(code, redirectUri);
            
            if (tokenResponse != null && tokenResponse.containsKey("access_token")) {
                String accessToken = (String) tokenResponse.get("access_token");
                
                // Token'dan kullanıcı bilgilerini al
                Map<String, Object> userInfo = keycloakAuthService.getUserInfoFromToken(accessToken);
                
                if (userInfo != null) {
                    // Session'da kullanıcı bilgilerini ve token'ı sakla
                    session.setAttribute("userInfo", userInfo);
                    session.setAttribute("keycloak_token", accessToken);
                    session.setAttribute("accessToken", accessToken); // PermissionHelper için
                    
                    // Rolleri session'a ekle
                    List<String> userRoles = keycloakAuthService.getUserRoles(accessToken);
                    session.setAttribute("userRoles", userRoles);
                    
                    // Permissions'ları session'a ekle
                    Map<String, Set<String>> userPermissions = keycloakAuthService.getAllUserPermissions(accessToken);
                    session.setAttribute("userPermissions", userPermissions);
                    
                    // UserInfo'yu session'a ekle
                    session.setAttribute("userInfo", userInfo);
                    
                    // 🚀 OTOMATIK PERMISSION CHECK
                    Map<String, Object> allPermissionResults = keycloakAuthService.checkAllPermissionsAutomatically(accessToken);
                    session.setAttribute("allPermissionResults", allPermissionResults);
                    
                    // Debug: Session'a ne kaydedildiğini kontrol et
                    System.out.println("🔍 SESSION DEBUG:");
                    System.out.println("   - userRoles session'a kaydedildi: " + (session.getAttribute("userRoles") != null));
                    System.out.println("   - userPermissions session'a kaydedildi: " + (session.getAttribute("userPermissions") != null));
                    System.out.println("   - userRoles değeri: " + userRoles);
                    System.out.println("   - userPermissions değeri: " + userPermissions);
                    
                    // JWT verilerini session'a kaydet (sessizce)
                    try {
                        String[] parts = accessToken.split("\\.");
                        if (parts.length == 3) {
                            String payload = new String(java.util.Base64.getDecoder().decode(parts[1]));
                            
                            // JSON parse et
                            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                            Map<String, Object> tokenData = mapper.readValue(payload, Map.class);
                            
                            // JWT verilerini session'a kaydet
                            if (tokenData.containsKey("scope")) {
                                String scopeStr = (String) tokenData.get("scope");
                                if (scopeStr != null && !scopeStr.isEmpty()) {
                                    List<String> scopes = java.util.Arrays.asList(scopeStr.split(" "));
                                    session.setAttribute("jwt_scope", scopes);
                                }
                            }
                            
                            if (tokenData.containsKey("realm_access")) {
                                Map<String, Object> realmAccess = (Map<String, Object>) tokenData.get("realm_access");
                                if (realmAccess != null && realmAccess.containsKey("roles")) {
                                    List<String> realmRoles = (List<String>) realmAccess.get("roles");
                                    session.setAttribute("jwt_realm_access", realmRoles);
                                }
                            }
                            
                            if (tokenData.containsKey("resource_access")) {
                                Map<String, Object> resourceAccess = (Map<String, Object>) tokenData.get("resource_access");
                                session.setAttribute("jwt_resource_access", resourceAccess);
                            }
                            
                            // Token metadata bilgilerini de kaydet
                            if (tokenData.containsKey("iss")) {
                                session.setAttribute("jwt_issuer", tokenData.get("iss"));
                            }
                            if (tokenData.containsKey("aud")) {
                                session.setAttribute("jwt_audience", tokenData.get("aud"));
                            }
                            if (tokenData.containsKey("sub")) {
                                session.setAttribute("jwt_subject", tokenData.get("sub"));
                            }
                            if (tokenData.containsKey("exp")) {
                                Long exp = (Long) tokenData.get("exp");
                                if (exp != null) {
                                    java.util.Date expiryDate = new java.util.Date(exp * 1000);
                                    session.setAttribute("jwt_expires", expiryDate.toString());
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Sessizce hata yut
                    }
                    
                    // User token'ı terminal'e bastır
                    System.out.println("🔑 KEYCLOAK USER TOKEN ALINDI!");
                    System.out.println("👤 Kullanıcı: " + userInfo.get("preferred_username"));
                    System.out.println("📧 Email: " + userInfo.get("email"));
                    System.out.println("🆔 User ID: " + userInfo.get("sub"));
                    
                    // Rolleri de göster
                    System.out.println("🎭 Kullanıcı Rolleri: " + userRoles);
                    
                    // Dinamik Permission kontrolü - Keycloak'tan gelen bilgiler
                    System.out.println("🔐 PERMISSION KONTROLÜ:");
                    System.out.println("📋 Kullanıcı Permissions: " + userPermissions);
                    
                    // Resources test'i ekleyelim
                    System.out.println("🏗️ RESOURCES TEST:");
                    List<Map<String, Object>> resources = keycloakAuthService.getResources();
                    System.out.println("📦 Keycloak Resources: " + resources.size());
                    for (Map<String, Object> resource : resources) {
                        System.out.println("   - " + resource.get("name") + " (" + resource.get("type") + ")");
                    }
                    
                    System.out.println("🔐 Access Token (100 char): " + accessToken.substring(0, Math.min(100, accessToken.length())) + "...");
                    System.out.println("🔐 Access Token (Tam): " + accessToken);
                    System.out.println("⏰ Zaman: " + new java.util.Date());
                    System.out.println("📝 Session ID: " + session.getId());
                    System.out.println("🎯 Dashboard'a yönlendiriliyor...");
                    
                    return "redirect:/dashboard";
                } else {
                    model.addAttribute("error", "Kullanıcı bilgileri alınamadı");
                    return "login";
                }
            } else {
                model.addAttribute("error", "Token alınamadı");
                return "login";
            }
        } catch (Exception e) {
            model.addAttribute("error", "Giriş işlemi sırasında hata: " + e.getMessage());
            return "login";
        }
    }
    
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        // Session'ı temizle
        session.invalidate();
        
        // Keycloak'tan da çıkış yap
        String logoutUrl = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/logout" +
                          "?client_id=" + clientId +
                          "&post_logout_redirect_uri=http://localhost:8080/login";
        
        return "redirect:" + logoutUrl;
    }
} 