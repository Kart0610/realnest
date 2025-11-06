package com.example.realnest.controller;

import com.example.realnest.entity.Property;
import com.example.realnest.entity.User;
import com.example.realnest.service.PropertyService;
import com.example.realnest.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class PropertyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private PropertyService propertyService;

    @MockBean
    private UserService userService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testGetAllProperties() throws Exception {
        User owner = new User(1L, "Alice", "alice@example.com", "pass", User.Role.ROLE_CUSTOMER);
        List<Property> properties = Arrays.asList(
                new Property(1L, "Title1", "Desc1", BigDecimal.valueOf(1000), Property.Type.SALE, "Loc1", null, true, null, owner),
                new Property(2L, "Title2", "Desc2", BigDecimal.valueOf(2000), Property.Type.RENT, "Loc2", null, true, null, owner)
        );

        Mockito.when(propertyService.getAllProperties()).thenReturn(properties);

        mockMvc.perform(get("/api/properties")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Title1")))
                .andExpect(content().string(containsString("Title2")));
    }

    @Test
    void testGetApprovedProperties() throws Exception {
        User owner = new User(1L, "Alice", "alice@example.com", "pass", User.Role.ROLE_CUSTOMER);
        List<Property> approvedProperties = Arrays.asList(
                new Property(1L, "Title1", "Desc1", BigDecimal.valueOf(1000), Property.Type.SALE, "Loc1", null, true, null, owner)
        );

        Mockito.when(propertyService.getApprovedProperties()).thenReturn(approvedProperties);

        mockMvc.perform(get("/api/properties/approved")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Title1")));
    }

    @Test
    void testGetUserProperties() throws Exception {
        User owner = new User(1L, "Alice", "alice@example.com", "pass", User.Role.ROLE_CUSTOMER);
        List<Property> userProperties = Arrays.asList(
                new Property(1L, "Title1", "Desc1", BigDecimal.valueOf(1000), Property.Type.SALE, "Loc1", null, true, null, owner)
        );

        Mockito.when(userService.findByEmail("alice@example.com")).thenReturn(Optional.of(owner));
        Mockito.when(propertyService.getPropertiesByOwner(owner)).thenReturn(userProperties);

        mockMvc.perform(get("/api/properties/owner")
                        .param("email", "alice@example.com")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Title1")));
    }

    @Test
    void testSearchProperties() throws Exception {
        User owner = new User(1L, "Alice", "alice@example.com", "pass", User.Role.ROLE_CUSTOMER);
        List<Property> searchResults = Arrays.asList(
                new Property(1L, "Title1", "Desc1", BigDecimal.valueOf(1000), Property.Type.SALE, "Loc1", null, true, null, owner)
        );

        Mockito.when(propertyService.searchProperties("Loc1", Property.Type.SALE, BigDecimal.valueOf(500), BigDecimal.valueOf(1500), "Title"))
                .thenReturn(searchResults);

        mockMvc.perform(get("/api/properties/search")
                        .param("location", "Loc1")
                        .param("type", "SALE")
                        .param("minPrice", "500")
                        .param("maxPrice", "1500")
                        .param("keyword", "Title")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Title1")));
    }

    @Test
    void testCreateProperty() throws Exception {
        User owner = new User(1L, "Alice", "alice@example.com", "pass", User.Role.ROLE_CUSTOMER);
        Property property = new Property(null, "Title1", "Desc1", BigDecimal.valueOf(1000), Property.Type.SALE, "Loc1", null, false, null, owner);

        Mockito.when(userService.findByEmail("alice@example.com")).thenReturn(Optional.of(owner));
        Mockito.when(propertyService.createProperty(Mockito.any(Property.class), Mockito.any())).thenReturn(property);

        MockMultipartFile propertyJson = new MockMultipartFile(
                "property", "", "application/json", objectMapper.writeValueAsBytes(property)
        );

        mockMvc.perform(multipart("/api/properties/create")
                        .file(propertyJson)
                        .param("ownerEmail", "alice@example.com")
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Title1")));
    }
    @Test
    void testUpdateProperty() throws Exception {
    // Mock owner
    User owner = new User(1L, "Alice", "alice@example.com", "pass", User.Role.ROLE_CUSTOMER);
    
    // Property object to send and expect
    Property property = new Property(1L, "Updated Title", "Updated Desc", 
            BigDecimal.valueOf(1500), Property.Type.SALE, "Updated Location", null, true, null, owner);

    // Mock service to return the updated property
    Mockito.when(propertyService.updateProperty(Mockito.eq(1L), Mockito.any(Property.class), Mockito.any()))
            .thenReturn(property);

    // Convert property to JSON bytes
    byte[] propertyJsonBytes = new ObjectMapper().writeValueAsBytes(property);

    // Create MockMultipartFile with name "property" to match @RequestPart("property")
    MockMultipartFile propertyPart = new MockMultipartFile(
            "property",            // must match @RequestPart("property")
            "", 
            "application/json", 
            propertyJsonBytes
    );

    // Perform the multipart PUT request
    mockMvc.perform(multipart("/api/properties/update/1")
                    .file(propertyPart)
                    .contentType(MediaType.MULTIPART_FORM_DATA)
                    .with(request -> { request.setMethod("PUT"); return request; })) // Important: force PUT
            .andExpect(status().isOk())
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Updated Title")));
     }


    @Test
    void testDeleteProperty() throws Exception {
        Mockito.doNothing().when(propertyService).deleteProperty(1L, "alice@example.com");

        mockMvc.perform(delete("/api/properties/delete/1")
                        .param("email", "alice@example.com"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Property deleted successfully")));
    }

    @Test
    void testApproveProperty() throws Exception {
        User owner = new User(1L, "Alice", "alice@example.com", "pass", User.Role.ROLE_CUSTOMER);
        Property property = new Property(1L, "Title1", "Desc1", BigDecimal.valueOf(1000), Property.Type.SALE, "Loc1", null, true, null, owner);

        Mockito.when(propertyService.approveProperty(1L)).thenReturn(property);

        mockMvc.perform(put("/api/properties/approve/1"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Title1")));
    }
}