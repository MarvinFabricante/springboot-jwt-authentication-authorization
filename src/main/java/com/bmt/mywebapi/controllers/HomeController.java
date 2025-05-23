package com.bmt.mywebapi.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @GetMapping("/")
    public String home(){
        return "Home page";
    }

    @GetMapping("/store")
    public String store() {
        return "Store page";
    }
}
