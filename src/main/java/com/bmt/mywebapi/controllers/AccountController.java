package com.bmt.mywebapi.controllers;

import com.bmt.mywebapi.models.AppUser;
import com.bmt.mywebapi.models.LoginDto;
import com.bmt.mywebapi.models.RegisterDto;
import com.bmt.mywebapi.repositories.AppUserRepository;
import com.bmt.mywebapi.services.JwtService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;

@RestController
@RequestMapping("/account")
public class AccountController {

    // This repository allows us to save the users to database
    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private JwtService jwtService;

    // This object allows us to verify if the user credentials are valid or not.
    @Autowired
    private AuthenticationManager authenticationManager;

    // this method allows user to see his profile.
    @GetMapping("/profile")
    public ResponseEntity<Object> profile(Authentication auth) {
        var response  = new HashMap<String, Object>();
        response.put("Username", auth.getName());
        response.put("Authorities", auth.getAuthorities());

        var appUser = appUserRepository.findByEmail(auth.getName());
        response.put("User", appUser);

        return ResponseEntity.ok(response);
    }

    // route to register users
    @PostMapping("/register")
    public ResponseEntity<Object> register(
            @Valid @RequestBody RegisterDto registerDto, BindingResult result) {

        if (result.hasErrors()) {
            var errorsList = result.getAllErrors();
            var errorsMap = new HashMap<String, String>();

            for (int i = 0; i < errorsList.size(); i++) {
                var error = (FieldError) errorsList.get(i);
                errorsMap.put(error.getField(), error.getDefaultMessage());
            }

            return ResponseEntity.badRequest().body(errorsMap);
        }

        AppUser appUser = new AppUser();
        appUser.setFirstName(registerDto.getFirstName());
        appUser.setLastName(registerDto.getLastName());
        appUser.setEmail(registerDto.getEmail());
        appUser.setPhone(registerDto.getPhone());
        appUser.setAddress(registerDto.getAddress());
        appUser.setRole("client");
        appUser.setCreatedAt(new Date());

        var bCryptEncoder = new BCryptPasswordEncoder();
        appUser.setPassword(bCryptEncoder.encode(registerDto.getPassword()));

        try {
            // check if username / email are used or not
            var otherUser = appUserRepository.findByEmail(registerDto.getEmail());
            if (otherUser != null) {
                return ResponseEntity.badRequest().body("Email address already used");
            }

            // this will save the user in the database using this appUserRepository
            appUserRepository.save(appUser);

            // and this generates a new JWT to new user
            String jwtToken = jwtService.createJwtToken(appUser);

            var response  = new HashMap<String, Object>();
            response.put("token", jwtToken);
            response.put("user", appUser);

            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            System.out.println("There is an exception : " + ex.getMessage());
        }

        return ResponseEntity.badRequest().body("Error");
    }

    // this route allows us to authenticate users
    @PostMapping("login")
    public ResponseEntity<Object> login(
            @Valid @RequestBody LoginDto loginDto,
            BindingResult result) {

        if (result.hasErrors()) {
            var errorsList = result.getAllErrors();
            var errorsMap = new HashMap<String, String>();

            for (int i = 0; i < errorsList.size(); i++) {
                var error  = (FieldError) errorsList.get(i);
                errorsMap.put(error.getField(), error.getDefaultMessage());
            }

            // it will return a bad request if there was a validation error
            return ResponseEntity.badRequest().body(errorsMap);
        }

        try {
            authenticationManager.authenticate(
                    // this will check if the username and password are valid or not.
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getEmail(),
                            loginDto.getPassword()
                    )
            );

            // this will read the user details from the database using our repository
            AppUser appUser = appUserRepository.findByEmail(loginDto.getEmail());

            String jwtToken = jwtService.createJwtToken(appUser);

            var response = new HashMap<String, Object>();
            response.put("token", jwtToken);
            response.put("user", appUser);

            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            System.out.println("There is an exception: " + ex.getMessage());
        }

        return ResponseEntity.badRequest().body("Bad username or password");
    }

}
