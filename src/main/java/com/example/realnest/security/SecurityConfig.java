// src/main/java/com/example/realnest/config/SecurityConfig.java
package com.example.realnest.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf().disable()
            .authorizeHttpRequests()
            
            // Public Thymeleaf pages
           .requestMatchers(
                          "/", 
                          "/login", 
                          "/register", 
                          "/properties/**", // API and pages
                          "/api/auth/**",
                          "/api/properties/**",
                          "/webpages/**",
                          "/dashboard",
                          "admin/dashboard",
                          "/css/**", 
                          "/js/**", 
                          "/images/**",
                           "/swagger-ui/**",
                           "/v3/api-docs/**",
                           "/swagger-ui.html",
                           "/swagger-ui/index.html",
                           "/swagger",
                            "/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/swagger-resources/**",
                    "/webjars/**","/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html"
                                                            
                ).permitAll()

            
            // Admin pages
            .requestMatchers("/admin/**", "/api/admin/**").hasRole("ADMIN")
            
            // Customer pages
            .requestMatchers("/dashboard/**").hasAnyRole("CUSTOMER", "ADMIN")
            .requestMatchers("/admin-dashboard").hasRole("ADMIN")
            
            // All other requests require authentication
            .anyRequest().authenticated()
            
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Add JWT filter
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}