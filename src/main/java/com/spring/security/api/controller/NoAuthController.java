package com.spring.security.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/noAuth/rest")
public class NoAuthController {
    /**
     * OPEN URL Test without auth
     *
     * @return
     */
    @GetMapping("/sayHi")
    public String sayHi() {
        return "hi: No USer auth required";
    }

}
