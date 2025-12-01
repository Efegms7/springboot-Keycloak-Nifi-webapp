
package com.example.demo;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;

@Controller
public class HomeController {

    @GetMapping("/")
    public String redirectToLogin() {
        return "redirect:/login";
    }
    
    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        Object userObj = session.getAttribute("userInfo");
        if (userObj == null) {
            return "redirect:/login";
        }
        
        model.addAttribute("user", userObj);
        
        // Keycloak bilgilerini de ekle
        if (session.getAttribute("keycloak_token") != null) {
            model.addAttribute("userRoles", session.getAttribute("userRoles"));
            model.addAttribute("userPermissions", session.getAttribute("userPermissions"));
        }
        
        return "dashboard";
    }
    
    @GetMapping("/projects")
    public String projects(HttpSession session, Model model) {
        Object userObj = session.getAttribute("userInfo");
        if (userObj == null) {
            return "redirect:/login";
        }
        
        model.addAttribute("user", userObj);
        
        // Keycloak bilgilerini de ekle
        if (session.getAttribute("keycloak_token") != null) {
            model.addAttribute("userRoles", session.getAttribute("userRoles"));
            model.addAttribute("userPermissions", session.getAttribute("userPermissions"));
        }
        
        return "projects";
    }
}
