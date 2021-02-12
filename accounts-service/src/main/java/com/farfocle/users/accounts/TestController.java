package com.farfocle.users.accounts;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/test", produces = "application/json")
public class TestController {

    @GetMapping("hello")
    public String helloWorld(){
        return "Siemano";
    }
}
