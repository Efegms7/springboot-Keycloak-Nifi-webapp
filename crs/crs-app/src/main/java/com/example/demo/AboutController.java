package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpSession;

@Controller
public class AboutController {
    
    @GetMapping("/about")
    public String about(HttpSession session, Model model) {
        // Keycloak bilgilerini ekle
        if (session.getAttribute("keycloak_token") != null) {
            model.addAttribute("userRoles", session.getAttribute("userRoles"));
            model.addAttribute("userPermissions", session.getAttribute("userPermissions"));
        }
        
        return "about";
    }
} 