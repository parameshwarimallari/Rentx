package com.rentx.carrental.entity;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "car")
@Data
public class Car {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "car_id")
    private Long carId;

    @Column(name = "available")
    private Boolean available;

    @Column(name = "brand")
    private String brand;

    @Enumerated(EnumType.STRING)
    @Column(name = "category")
    private CarCategory category;

    @Column(name = "color")
    private String color;

    @Column(name = "daily_rate")
    private Double dailyRate;

    @Column(name = "license_plate")
    private String licensePlate;

    @Column(name = "model")
    private String model;

    @Column(name = "year")
    private Integer year;

    @Column(name = "active")
    private Boolean active;

    @Column(name = "image_path")
    private String imagePath;

    public enum CarCategory {
        COMPACT, ECONOMY, PREMIUM, STANDARD, SUV
    }
    @JsonIgnore
    @OneToMany(mappedBy = "car")
    private List<Booking> bookings;
    @JsonIgnore
    @OneToMany(mappedBy = "car")
    private List<Review> reviews;
}