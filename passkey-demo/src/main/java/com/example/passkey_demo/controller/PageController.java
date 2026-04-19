package com.example.passkey_demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("isAuthenticated", false);
        return "index";
    }

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("isAuthenticated", false);
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        model.addAttribute("isAuthenticated", false);
        return "register";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        model.addAttribute("isAuthenticated", true);
        return "dashboard";
    }
}
