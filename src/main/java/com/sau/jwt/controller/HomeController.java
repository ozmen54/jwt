package com.sau.jwt.controller;

import com.sau.jwt.DTOs.LoginRequest;
import com.sau.jwt.security.JwtUtility;
import com.sau.jwt.security.UserDetailsServiceDAO;
import com.sau.jwt.security.UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@AllArgsConstructor
public class HomeController {
    //@Autowired
    private final UserService userService;
    private final JwtUtility jwtUtility;

    @GetMapping("/")
    public String getHome(){
        System.out.println("Here");
        return "index";
    }

    @GetMapping("/login")
    public String getLogin(){
        return "login";
    }

    @PostMapping("/login")
    @ResponseBody
    public String authenticateAndGetToken(LoginRequest request){
        String token = userService.loginAndCreateAuthenticationToken(request);
        System.out.println("Token: " + token);
        return token;
    }
}
