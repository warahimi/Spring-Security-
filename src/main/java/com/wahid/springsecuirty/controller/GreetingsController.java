package com.wahid.springsecuirty.controller;

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
}
