package com.example.realnest.repository;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.realnest.entity.Property;
import com.example.realnest.entity.User;

public interface PropertyRepository extends JpaRepository<Property, Long>{
    
    // Find properties by owner
    List<Property> findByOwnerId(Long ownerId);
    
    // Find by location containing keyword (case-insensitive)
    List<Property> findByLocationContainingIgnoreCase(String location);
    
    // Find by type
    List<Property> findByType(Property.Type type);
    
    // Find by price range
    List<Property> findByPriceBetween(BigDecimal minPrice, BigDecimal maxPrice);
    
    // Search by title or description keyword
    List<Property> findByTitleContainingIgnoreCaseOrDescriptionContainingIgnoreCase(String title, String description);
    
    // Combine multiple criteria (example: location + type + price range)
    List<Property> findByLocationContainingIgnoreCaseAndTypeAndPriceBetween(
            String location, Property.Type type, BigDecimal minPrice, BigDecimal maxPrice);

    List<Property> findByApprovedTrue();
    List<Property> findByApprovedTrueAndLocationContainingIgnoreCase(String location);
    List<Property> findByApprovedTrueAndType(Property.Type type);
         List<Property> findByOwner(User owner);

}
