package com.example.realnest.controller;


import com.example.realnest.entity.User;
import com.example.realnest.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "User API", description = "Admin-only user management endpoints")
@RestController
@RequestMapping("/api/admin")
public class UserController {

    @Autowired
    private UserService userService;

    @Operation(summary = "Get all users", description = "Fetch all registered users (Admin only)")
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userService.showAllUsers());
    }

    @Operation(summary = "Get user by email", description = "Fetch a single user by email")
    @GetMapping("/by-email/{email}")
    public ResponseEntity<?> getUserByEmail(@PathVariable String email) {
        return ResponseEntity.ok(userService.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found")));
    }

    @Operation(summary = "Update user by id", description = "Update user details by id (Admin only)")
    @PutMapping("update/{id}")
    public ResponseEntity<?> updateUserById(@PathVariable Long id, @RequestBody User user) {
        return ResponseEntity.ok(userService.updateUser(id, user));
    }

   // ✅ Delete user (with all properties)
    @Operation(summary = "Delete user by ID (and all their properties)")
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteUserById(@PathVariable Long id) {
        try {
            userService.deleteuser(id);
            return ResponseEntity.ok("User and all related properties deleted successfully!");
        } catch (RuntimeException ex) {
            return ResponseEntity.badRequest().body("Error: " + ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.internalServerError().body("Unexpected error: " + ex.getMessage());
        }
    }
}