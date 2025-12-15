package com.rentx.carrental.controller;

import com.rentx.carrental.entity.Review;
import com.rentx.carrental.service.ReviewService;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/reviews")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class ReviewController {
	private final ReviewService reviewService;

	@PostMapping
	public ResponseEntity<?> createReview(@RequestBody ReviewRequest request) {
		try {
			Review review = reviewService.createReview(request.getBookingId(), request.getRating(),
					request.getComment());
			return ResponseEntity.ok(review);
		} catch (Exception e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

	@GetMapping("/car/{carId}")
	public ResponseEntity<List<Review>> getCarReviews(@PathVariable Long carId) {
		return ResponseEntity.ok(reviewService.getCarReviews(carId));
	}

	@GetMapping("/car/{carId}/rating")
	public ResponseEntity<Map<String, Object>> getCarRating(@PathVariable Long carId) {
		Double averageRating = reviewService.getCarAverageRating(carId);
		Long reviewCount = reviewService.getCarReviewCount(carId);

		Map<String, Object> response = new HashMap<>();
		response.put("averageRating", averageRating != null ? Math.round(averageRating * 10.0) / 10.0 : 0);
		response.put("reviewCount", reviewCount);
		response.put("carId", carId);

		return ResponseEntity.ok(response);
	}

	@Data
	public static class ReviewRequest {
		private Long bookingId;
		private Integer rating;
		private String comment;
	}
}