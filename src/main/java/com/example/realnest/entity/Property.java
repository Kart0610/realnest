package com.example.realnest.entity;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Property {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String title;

    @NotBlank
    private String description;

    @NotNull
    private BigDecimal price;

     @Enumerated(EnumType.STRING)
         private Type type; // SALE or RENT
         
    @NotBlank
    private String location;

    private String imageUrl;

    private boolean approved = false;

    private LocalDateTime dateListed = LocalDateTime.now();


    @ManyToOne
    @JoinColumn(name = "owner_id")
    private User owner;
    public enum Type { SALE, RENT }

}
