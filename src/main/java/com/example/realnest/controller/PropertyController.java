package com.example.realnest.controller;

import com.example.realnest.entity.Property;
import com.example.realnest.entity.User;
import com.example.realnest.service.PropertyService;
import com.example.realnest.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import jakarta.validation.Valid;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.web.bind.annotation.RestController;


@Tag(name = "Property API", description = "Manage property listings")
@RestController
@RequestMapping("/api/properties")
public class PropertyController {

    @Autowired
    private PropertyService propertyService;

    @Autowired
    private UserService userService;

    @Operation(summary = "Get all properties", description = "Fetch all properties from the database")
    @GetMapping
    public ResponseEntity<List<Property>> getAllProperties() {
        return ResponseEntity.ok(propertyService.getAllProperties());
    }

    @Operation(summary = "Get approved properties", description = "Fetch all approved properties")
    @GetMapping("/approved")
    public ResponseEntity<List<Property>> getApprovedProperties() {
        return ResponseEntity.ok(propertyService.getApprovedProperties());
    }

    @Operation(summary = "Get properties by owner", description = "Fetch properties owned by a specific user")
    @GetMapping("/owner")
    public ResponseEntity<List<Property>> getUserProperties(@RequestParam String email) {
        User owner = userService.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(propertyService.getPropertiesByOwner(owner));
    }

    @Operation(summary = "Update a property", description = "Update property details (Admin/Owner access)")
    @PutMapping("/update/{id}")
    public ResponseEntity<Property> updateProperty(
            @PathVariable Long id,
            @RequestPart("property") String propertyJson,
            @RequestPart(value = "imageFile", required = false) MultipartFile imageFile
    ) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Property property = mapper.readValue(propertyJson, Property.class);
        Property updated = propertyService.updateProperty(id, property, imageFile);
        return ResponseEntity.ok(updated);
    }

    @Operation(summary = "Delete a property", description = "Delete property by id (Admin/Owner access)")
    @PreAuthorize("hasAnyRole('ADMIN','CUSTOMER')")
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteProperty(@PathVariable Long id, @RequestParam String email) {
        propertyService.deleteProperty(id, email);
        return ResponseEntity.ok("Property deleted successfully");
    }

    @Operation(summary = "Approve a property", description = "Approve property listing (Admin only)")
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/approve/{id}")
    public ResponseEntity<Property> approveProperty(@PathVariable Long id) {
        return ResponseEntity.ok(propertyService.approveProperty(id));
    }

    @Operation(summary = "Search properties", description = "Search properties with filters")
    @GetMapping("/search")
    public ResponseEntity<List<Property>> searchProperties(
            @RequestParam(required = false) String location,
            @RequestParam(required = false) Property.Type type,
            @RequestParam(required = false) BigDecimal minPrice,
            @RequestParam(required = false) BigDecimal maxPrice,
            @RequestParam(required = false) String keyword
    ) {
        return ResponseEntity.ok(propertyService.searchProperties(location, type, minPrice, maxPrice, keyword));
    }

    @Operation(summary = "Create a property", description = "Create new property listing")
    @PostMapping("/create")
    public ResponseEntity<Property> createProperty(
            @RequestPart("property") @Valid String propertyJson,
            @RequestPart(value = "imageFile", required = false) MultipartFile imageFile,
            @RequestParam String ownerEmail) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        Property property = mapper.readValue(propertyJson, Property.class);

        User owner = userService.findByEmail(ownerEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));
        property.setOwner(owner);

        Property saved = propertyService.createProperty(property, imageFile);
        return ResponseEntity.ok(saved);
    }
}