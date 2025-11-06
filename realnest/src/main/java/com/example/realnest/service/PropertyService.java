package com.example.realnest.service;

import com.example.realnest.entity.Property;
import com.example.realnest.entity.User;
import com.example.realnest.repository.PropertyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;

@Service
public class PropertyService {

    @Autowired
    private PropertyRepository propertyRepository;

    @Autowired
    private CloudinaryService cloudinaryService;

    @Autowired
    private UserService userService;

    // Get all properties
    public List<Property> getAllProperties() {
        return propertyRepository.findAll();
    }

    // Get all approved properties
    public List<Property> getApprovedProperties() {
        return propertyRepository.findAll().stream()
                .filter(Property::isApproved)
                .toList();
    }

    // Get properties by owner
    public List<Property> getPropertiesByOwner(User owner) {
        return propertyRepository.findByOwnerId(owner.getId());
    }

    // Get property by ID
    public Property getPropertyById(Long id) {
        return propertyRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Property not found"));
    }

    // Create a new property
    public Property createProperty(Property property, MultipartFile imageFile) throws IOException {
        if (imageFile != null && !imageFile.isEmpty()) {
            String imageUrl = cloudinaryService.upload(imageFile);
            property.setImageUrl(imageUrl);
        }
        property.setApproved(false);
        return propertyRepository.save(property);
    }

    // Update existing property
    public Property updateProperty(Long id, Property property, MultipartFile imageFile) throws IOException {
        Property existing = propertyRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Property not found"));

        existing.setTitle(property.getTitle());
        existing.setDescription(property.getDescription());
        existing.setPrice(property.getPrice());
        existing.setType(property.getType());
        existing.setLocation(property.getLocation());

        if (imageFile != null && !imageFile.isEmpty()) {
            String imageUrl = cloudinaryService.upload(imageFile);
            existing.setImageUrl(imageUrl);
        }

        return propertyRepository.save(existing);
    }

    // Delete property with proper authorization
    public void deleteProperty(Long id, String requesterEmail) {
        Property property = propertyRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Property not found"));

        User requester = userService.findByEmail(requesterEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (property.getOwner().getEmail().equals(requesterEmail) || requester.getRole() == User.Role.ROLE_ADMIN) {
            propertyRepository.deleteById(id);
        } else {
            throw new RuntimeException("Unauthorized to delete this property");
        }
    }

    // Search properties with optional filters
    public List<Property> searchProperties(String location, Property.Type type, BigDecimal minPrice, BigDecimal maxPrice, String keyword) {
        return propertyRepository.findAll().stream()
                .filter(p -> location == null || p.getLocation().toLowerCase().contains(location.toLowerCase()))
                .filter(p -> type == null || p.getType() == type)
                .filter(p -> minPrice == null || p.getPrice().compareTo(minPrice) >= 0)
                .filter(p -> maxPrice == null || p.getPrice().compareTo(maxPrice) <= 0)
                .filter(p -> keyword == null || p.getTitle().toLowerCase().contains(keyword.toLowerCase()) ||
                             (p.getDescription() != null && p.getDescription().toLowerCase().contains(keyword.toLowerCase())))
                .toList();
    }

    // Approve property
    public Property approveProperty(Long id) {
        Property property = propertyRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Property not found"));
        property.setApproved(true);
        return propertyRepository.save(property);
    }
}