package com.example.realnest.controller;

import com.example.realnest.entity.User;
import com.example.realnest.service.UserService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Test
    void testGetAllUsers() throws Exception {
        User user1 = new User(1L, "John Doe", "john@example.com", "password", User.Role.ROLE_CUSTOMER);
        User user2 = new User(2L, "Alice Smith", "alice@example.com", "password", User.Role.ROLE_CUSTOMER);

        List<User> users = Arrays.asList(user1, user2);
        Mockito.when(userService.showAllUsers()).thenReturn(users);

        mockMvc.perform(get("/api/admin/users")
                        .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("admin@example.com").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("John Doe")))
                .andExpect(content().string(containsString("Alice Smith")));
    }

    @Test
    void testGetUserByEmail() throws Exception {
        User user = new User(1L, "John Doe", "john@example.com", "password", User.Role.ROLE_CUSTOMER);
        Mockito.when(userService.findByEmail("john@example.com")).thenReturn(Optional.of(user));

        mockMvc.perform(get("/api/admin/by-email/john@example.com")
                        .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("admin@example.com").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("John Doe")))
                .andExpect(content().string(containsString("john@example.com")));
    }

    @Test
    void testUpdateUserById() throws Exception {
        User updatedUser = new User(1L, "John Updated", "john@example.com", "newpass", User.Role.ROLE_CUSTOMER);
        Mockito.when(userService.updateUser(Mockito.eq(1L), Mockito.any(User.class))).thenReturn(updatedUser);

        String json = """
                {
                    "name": "John Updated",
                    "email": "john@example.com",
                    "password": "newpass",
                    "role": "ROLE_CUSTOMER"
                }
                """;

        mockMvc.perform(put("/api/admin/update/1")
                        .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("admin@example.com").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("John Updated")));
    }

    @Test
    void testDeleteUserById() throws Exception {
        Mockito.doNothing().when(userService).deleteuser(1L);

        mockMvc.perform(delete("/api/admin/delete/1")
                        .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("admin@example.com").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("User and all related properties deleted successfully!")));
    }
}