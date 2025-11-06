package com.example.realnest.controller;

import com.example.realnest.entity.User;
import com.example.realnest.repository.UserRepository;
import com.example.realnest.security.CustomUserDetailsService;
import com.example.realnest.security.JwtUtil;
import com.example.realnest.service.UserService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private JwtUtil jwtUtil;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private CustomUserDetailsService customUserDetailsService;

    @Test
    void testRegister() throws Exception {
        User user = new User(null, "John Doe", "john@example.com", "pass123", User.Role.ROLE_CUSTOMER);
        Mockito.when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.empty());
        Mockito.when(passwordEncoder.encode(user.getPassword())).thenReturn("encodedPass");
        Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(user);

        String json = """
                {"name":"John Doe","email":"john@example.com","password":"pass123","role":"ROLE_CUSTOMER"}
                """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk());
    }

    @Test
    void testLogin() throws Exception {
        User user = new User(1L, "John Doe", "john@example.com", "pass123", User.Role.ROLE_CUSTOMER);
        Mockito.when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(user));
        Mockito.when(jwtUtil.generateToken(user)).thenReturn("dummyToken");

        String json = """
                {"email":"john@example.com","password":"pass123"}
                """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk());
    }
}