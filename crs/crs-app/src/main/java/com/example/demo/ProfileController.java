package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

@Controller
public class ProfileController {
    
    private static final Logger logger = LoggerFactory.getLogger(ProfileController.class);
    
    @Autowired
    private KeycloakAuthService keycloakAuthService;
    
    @GetMapping("/profile")
    public String profile(HttpSession session, Model model) {
        Object userObj = session.getAttribute("userInfo");
        Object tokenObj = session.getAttribute("keycloak_token");
        
        if (userObj == null || tokenObj == null) {
            return "redirect:/login";
        }
        
        @SuppressWarnings("unchecked")
        Map<String, Object> userInfo = (Map<String, Object>) userObj;
        String accessToken = (String) tokenObj;
        
        logger.info("Profile sayfasına erişim: {}", userInfo.get("username"));
        
        try {
            // Keycloak'tan gelen kullanıcı bilgilerini düzgün şekilde map et
            Map<String, Object> mappedUser = new java.util.HashMap<>();
            
            // Keycloak'tan gelen alanları template'deki alanlara map et
            mappedUser.put("firstName", userInfo.get("given_name") != null ? userInfo.get("given_name") : 
                          userInfo.get("preferred_username") != null ? userInfo.get("preferred_username") : "");
            mappedUser.put("lastName", userInfo.get("family_name") != null ? userInfo.get("family_name") : "");
            mappedUser.put("email", userInfo.get("email") != null ? userInfo.get("email") : "");
            mappedUser.put("username", userInfo.get("preferred_username") != null ? userInfo.get("preferred_username") : "");
            
            // Debug için log
            logger.info("Keycloak userInfo: {}", userInfo);
            logger.info("Mapped user: {}", mappedUser);
            
            model.addAttribute("user", mappedUser);
            
            // Keycloak bilgilerini de ekle
            if (tokenObj != null) {
                model.addAttribute("userRoles", session.getAttribute("userRoles"));
                model.addAttribute("userPermissions", session.getAttribute("userPermissions"));
            }
            
            return "profile";
            
        } catch (Exception e) {
            logger.error("Profile hatası: {}", e.getMessage());
            model.addAttribute("error", "Profil yüklenemedi");
            return "error";
        }
    }
    
    @PostMapping("/profile/update")
    public String updateProfile(@RequestParam String firstName,
                               @RequestParam String lastName,
                               @RequestParam String email,
                               HttpSession session,
                               Model model) {
        
        Object userObj = session.getAttribute("userInfo");
        if (userObj == null) {
            return "redirect:/login";
        }
        
        try {
            // Burada gerçek bir güncelleme işlemi yapılabilir
            // Şimdilik sadece başarı mesajı gösterelim
            
            logger.info("Profil güncellendi - Ad: {}, Soyad: {}, Email: {}", firstName, lastName, email);
            
            // Session'da güncellenmiş bilgileri sakla
            @SuppressWarnings("unchecked")
            Map<String, Object> userInfo = (Map<String, Object>) userObj;
            userInfo.put("given_name", firstName);
            userInfo.put("family_name", lastName);
            userInfo.put("email", email);
            
            session.setAttribute("userInfo", userInfo);
            
            // Başarı mesajı ile profile sayfasına geri dön
            model.addAttribute("success", "✅ Profil başarıyla güncellendi!");
            
            // Güncellenmiş bilgileri tekrar yükle
            return profile(session, model);
            
        } catch (Exception e) {
            logger.error("Profil güncelleme hatası: {}", e.getMessage());
            model.addAttribute("error", "❌ Profil güncellenirken hata oluştu: " + e.getMessage());
            return profile(session, model);
        }
    }
} 