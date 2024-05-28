package com.wahid.springsecuirty.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping
    public String root()
    {
        return "Welcome";
    }
    @GetMapping("/hello")
    public String sayHello()
    {
        return "Hello";
    }
    @GetMapping("/hello-world")
    public String sayHelloWorld()
    {
        return "Hello World";
    }

    @PreAuthorize("hasRole('USER')") // checkes authentication before executing the method
    @GetMapping("/user")
    public String sayHelloUser()
    {
        return "Hello User";
    }

    @GetMapping("/admin")
    public String sayHelloAdmin()
    {
        return "Hello Admin";
    }
}
