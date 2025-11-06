package com.example.realnest.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.realnest.entity.Property;
import com.example.realnest.entity.User;
import com.example.realnest.repository.PropertyRepository;
import com.example.realnest.repository.UserRepository;

import jakarta.transaction.Transactional;

import org.springframework.security.crypto.password.PasswordEncoder;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;
    
    @Autowired
    PropertyRepository propertyRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User registerUser(User user) {
        // Encode the password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRole() == null) user.setRole(User.Role.ROLE_CUSTOMER);
        return userRepository.save(user);
    }

    // Add user
    public User adduser(User user) {
        return userRepository.save(user);
    }

    //find by email
    public Optional<User>  findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

   
    // Delete user
    @Transactional
   public void deleteuser(Long id) {
    // Step 1: Find the user by ID
    User user = userRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("User not found"));

    // Step 2: Find and delete all properties owned by this user
    List<Property> userProperties = propertyRepository.findByOwner(user);
    if (!userProperties.isEmpty()) {
        propertyRepository.deleteAll(userProperties);
    }

    // Step 3: Delete the user
    userRepository.delete(user);
}


    //show all users
    public List<User> showAllUsers() {
        return userRepository.findAll();
    }  
    
    //find by id
    public User findById(Long id) {
        return userRepository.findById(id).get();
    }

    //update user by id
    public User updateUser(Long id, User user) {
        User existingUser = userRepository.findById(id).orElse(null);
        if (existingUser != null) {
            existingUser.setName(user.getName());
            existingUser.setEmail(user.getEmail());
            existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
            existingUser.setRole(user.getRole());
            return userRepository.save(existingUser);
        }
          return null;
    }
   }