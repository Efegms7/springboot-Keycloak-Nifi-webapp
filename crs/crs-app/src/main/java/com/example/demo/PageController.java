package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class PageController {

    @GetMapping("/nifi-page")
    public String nifiPage() {
        return "nifi"; // resources/templates/nifi.html dosyası olacak
    }
}
