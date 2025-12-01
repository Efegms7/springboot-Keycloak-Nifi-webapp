package com.example.demo;

import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import java.util.Set;

/**
 * Sayfa bazlı erişim kontrolü için yardımcı sınıf
 * Keycloak Authorization Services kullanarak permission kontrolü yapar
 * permsıın kontrolu varsa nerelere erişebilir? gibi ama bu kod yapısının çalışması için yardımcı bu sınfı olmadan da calısabılıyor.
 */
@Component
public class PermissionHelper {
    
    private static final Logger logger = LoggerFactory.getLogger(PermissionHelper.class);
    
    @Autowired
    private KeycloakAuthService keycloakAuthService;
    
    /**
     * Kullanıcının belirli bir sayfaya erişim yetkisi olup olmadığını kontrol eder
     * 
     * @param session HTTP session
     * @param pageName Sayfa adı (örn: "dashboard", "projects", "admin-panel")
     * @return true if user has access, false otherwise
     */
    public boolean hasPageAccess(HttpSession session, String pageName) {
        try {
            String accessToken = getAccessTokenFromSession(session);
            if (accessToken == null) {
                logger.warn("Session'da access token bulunamadı");
                return false;
            }
            
            // Sayfa bazlı permission mapping
            String resource = getResourceForPage(pageName);
            String scope = getScopeForPage(pageName);
            
            if (resource == null || scope == null) {
                logger.warn("Sayfa {} için resource/scope tanımlanmamış", pageName);
                return false;
            }
            
            boolean hasPermission = keycloakAuthService.hasPermission(accessToken, resource, scope);
            logger.debug("Sayfa {} için permission kontrolü: Resource={}, Scope={}, Result={}", 
                       pageName, resource, scope, hasPermission);
            
            return hasPermission;
            
        } catch (Exception e) {
            logger.error("Sayfa erişim kontrolü hatası: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Kullanıcının tüm sayfa permission'larını getirir
     * 
     * @param session HTTP session
     * @return Sayfa permission'ları map'i
     */
    public Map<String, Boolean> getAllPagePermissions(HttpSession session) {
        try {
            String accessToken = getAccessTokenFromSession(session);
            if (accessToken == null) {
                return Map.of();
            }
            
            // Tüm sayfalar için permission kontrolü
            Map<String, Boolean> permissions = Map.of(
                "dashboard", hasPageAccess(session, "dashboard"),
                "projects", hasPageAccess(session, "projects"),
                "admin-panel", hasPageAccess(session, "admin-panel"),
                "user-management", hasPageAccess(session, "user-management"),
                "profile", hasPageAccess(session, "profile"),
                "about", hasPageAccess(session, "about")
            );
            
            return permissions;
            
        } catch (Exception e) {
            logger.error("Tüm sayfa permission'ları getirme hatası: {}", e.getMessage());
            return Map.of();
        }
    }
    
    /**
     * Sayfa adına göre Keycloak resource adını döndürür
     * 
     * @param pageName Sayfa adı
     * @return Keycloak resource adı
     */
    private String getResourceForPage(String pageName) {
        return switch (pageName) {
            case "dashboard" -> "dashboard-page";
            case "projects" -> "projects-page";
            case "admin-panel" -> "admin-page";
            case "user-management" -> "user-management-page";
            case "profile" -> "profile-page";
            case "about" -> "about";  // Keycloak'taki gerçek resource adı
            default -> null;
        };
    }
    
    /**
     * Sayfa adına göre Keycloak scope adını döndürür
     * 
     * @param pageName Sayfa adı
     * @return Keycloak scope adı
     */
    private String getScopeForPage(String pageName) {
        return switch (pageName) {
            case "dashboard" -> "view";
            case "projects" -> "view";
            case "admin-panel" -> "admin";
            case "user-management" -> "manage";
            case "profile" -> "view";
            case "about" -> "read";  // Keycloak'taki scope adı
            default -> null;
        };
    }
    
    /**
     * Session'dan access token'ı alır
     * 
     * @param session HTTP session
     * @return Access token veya null
     */
    private String getAccessTokenFromSession(HttpSession session) {
        Object tokenObj = session.getAttribute("accessToken");
        if (tokenObj instanceof String) {
            return (String) tokenObj;
        }
        return null;
    }
    
    /**
     * Kullanıcının admin yetkisi olup olmadığını kontrol eder
     * 
     * @param session HTTP session
     * @return true if user is admin, false otherwise
     */
    public boolean isAdmin(HttpSession session) {
        return hasPageAccess(session, "admin-panel");
    }
    
    /**
     * Kullanıcının user management yetkisi olup olmadığını kontrol eder
     * 
     * @param session HTTP session
     * @return true if user can manage users, false otherwise
     */
    public boolean canManageUsers(HttpSession session) {
        return hasPageAccess(session, "user-management");
    }
}



