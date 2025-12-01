
package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class VerilerController {

    @GetMapping("/veriler")
    @ResponseBody
    public String veriler() {
        return "Veriler sayfası çalışıyor! 🎉";
        

    }
}
