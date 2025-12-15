package com.rentx.carrental.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.rentx.carrental.entity.Review;

@Repository
public interface ReviewRepository extends JpaRepository<Review, Long> {
    
    @Query("SELECT r FROM Review r WHERE r.car.carId = :carId ORDER BY r.createdAt DESC")
    List<Review> findByCarCarIdOrderByCreatedAtDesc(@Param("carId") Long carId);
    
    @Query("SELECT CASE WHEN COUNT(r) > 0 THEN true ELSE false END FROM Review r WHERE r.user.id = :userId AND r.booking.id = :bookingId")
    Boolean existsByUserIdAndBookingId(@Param("userId") Long userId, @Param("bookingId") Long bookingId);
    
    @Query("SELECT AVG(r.rating) FROM Review r WHERE r.car.carId = :carId")
    Double findAverageRatingByCarId(@Param("carId") Long carId);
    
    @Query("SELECT COUNT(r) FROM Review r WHERE r.car.carId = :carId")
    Long countByCarCarId(@Param("carId") Long carId);
    
    @Query("SELECT r FROM Review r WHERE r.booking.id = :bookingId")
    Optional<Review> findByBookingId(@Param("bookingId") Long bookingId);
}