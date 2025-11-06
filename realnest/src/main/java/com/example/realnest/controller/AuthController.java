package com.example.realnest.controller;



import com.example.realnest.entity.User;
import com.example.realnest.repository.UserRepository;
import com.example.realnest.security.JwtUtil;
import com.example.realnest.service.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private  UserService userService;
    @Autowired
    private  AuthenticationManager authenticationManager;
    @Autowired    
    private  JwtUtil jwtUtils;
    @Autowired
    private  PasswordEncoder passwordEncoder;
    @Autowired
    private  UserRepository userRepository;

    // Register new user
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        // Check if email already exists
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        // Encode password
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        // Set default role if not set
        if (user.getRole() == null) user.setRole(User.Role.ROLE_CUSTOMER);

        User savedUser = userRepository.save(user); // use repository directly
        return ResponseEntity.ok(savedUser);
    }

    // Login
   @PostMapping("/login")
public ResponseEntity<?> login(@RequestBody User user) {
    try {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword())
        );
        User loggedInUser = userRepository.findByEmail(user.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        String token = jwtUtils.generateToken(loggedInUser);
        return ResponseEntity.ok(token);
    } catch (BadCredentialsException e) {
        return ResponseEntity.status(401).body("Invalid email or password");
    }
}
}