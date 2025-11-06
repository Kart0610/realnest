package com.example.realnest.controller;

import com.example.realnest.entity.Property;
import com.example.realnest.service.PropertyService;
import com.example.realnest.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@Controller
@RequestMapping("/webpages")
public class ViewController {

    @Autowired
    private PropertyService propertyService;
    @Autowired
    private UserService userService;

    @GetMapping("/")
    public String home(Model model) {
        List<Property> properties = propertyService.getApprovedProperties();
        model.addAttribute("properties", properties);
        return "home";
    }

    @GetMapping("/login")
    public String loginPage(){ return "login"; }

    @GetMapping("/register")
    public String registerPage(){ return "register"; }

    @GetMapping("/dashboard")
    public String customerDashboard(){ return "dashboard"; }

    @GetMapping("/admin/dashboard")
    public String adminDashboard(){ return "admin-dashboard"; }

    @GetMapping("/properties/{id}")
    public String propertyDetail(@PathVariable Long id, Model model){
        Property property = propertyService.getPropertyById(id);
        model.addAttribute("property", property);
        return "property-details";
    }

    @GetMapping("/properties/new")
    public String newPropertyForm(){ return "property-form"; }

    @GetMapping("/properties/edit/{id}")
    public String editPropertyForm(){ return "property-form"; }
}