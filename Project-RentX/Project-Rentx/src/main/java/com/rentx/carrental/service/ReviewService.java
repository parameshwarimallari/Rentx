package com.rentx.carrental.service;

import java.time.LocalDateTime;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Review;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.ReviewRepository;
import com.rentx.carrental.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ReviewService {
    private final ReviewRepository reviewRepository;
    private final BookingRepository bookingRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    public Review createReview(Long bookingId, Integer rating, String comment) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

        if (!booking.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("You can only review your own bookings");
        }

        if (booking.getStatus() != Booking.BookingStatus.COMPLETED) {
            throw new RuntimeException("You can only review completed bookings");
        }

        if (rating < 1 || rating > 5) {
            throw new RuntimeException("Rating must be between 1 and 5");
        }

        if (reviewRepository.existsByUserIdAndBookingId(user.getId(), bookingId)) {
            throw new RuntimeException("You have already reviewed this booking");
        }

        Review review = new Review();
        review.setUser(user);
        review.setCar(booking.getCar());
        review.setBooking(booking);
        review.setRating(rating);
        review.setComment(comment);
        review.setCreatedAt(LocalDateTime.now());

        Review savedReview = reviewRepository.save(review);

        try {
            emailService.sendReviewConfirmation(user, savedReview);
        } catch (Exception e) {
            System.err.println("Failed to send review email: " + e.getMessage());
        }

        return savedReview;
    }

    public List<Review> getCarReviews(Long carId) {
        return reviewRepository.findByCarCarIdOrderByCreatedAtDesc(carId);
    }

    public Double getCarAverageRating(Long carId) {
        return reviewRepository.findAverageRatingByCarId(carId);
    }

    public Long getCarReviewCount(Long carId) {
        return reviewRepository.countByCarCarId(carId);
    }
}