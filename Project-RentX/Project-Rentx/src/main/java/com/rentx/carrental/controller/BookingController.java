package com.rentx.carrental.controller;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.rentx.carrental.dto.BookingRequest;
import com.rentx.carrental.dto.BookingResponse;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.exception.BookingNotFoundException;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.service.BookingService;
import com.rentx.carrental.service.EmailService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/bookings")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class BookingController {

	private final BookingService bookingService;
	private final BookingRepository bookingRepository;
	private final EmailService emailService;

	@PostMapping
	public ResponseEntity<BookingResponse> createBooking(@Valid @RequestBody BookingRequest request) {
		return ResponseEntity.ok(bookingService.createBooking(request));
	}

	@GetMapping("/user")
	public ResponseEntity<List<BookingResponse>> getUserBookings() {
		return ResponseEntity.ok(bookingService.getUserBookings());
	}

	@GetMapping("/{id}")
	public ResponseEntity<BookingResponse> getBookingById(@PathVariable Long id) {
		return ResponseEntity.ok(bookingService.getBookingById(id));
	}

	@PostMapping("/{id}/cancel")
	public ResponseEntity<?> cancelBooking(@PathVariable Long id, @RequestBody Map<String, String> request) {
		try {
			String reason = request.get("reason");
			BookingResponse cancelledBooking = bookingService.cancelBooking(id, reason);
			return ResponseEntity.ok(cancelledBooking);
		} catch (RuntimeException e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

	@PostMapping("/test-email/{bookingId}")
	public ResponseEntity<?> testEmail(@PathVariable Long bookingId) {
		try {
			Booking booking = bookingRepository.findById(bookingId)
					.orElseThrow(() -> new RuntimeException("Booking not found"));

			emailService.sendBookingConfirmation(booking.getUser(), booking);

			return ResponseEntity.ok("Test email sent to: " + booking.getUser().getEmail());
		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Email test failed: " + e.getMessage());
		}
	}

	@GetMapping("/user/filter/{filter}")
	public ResponseEntity<List<BookingResponse>> getUserBookingsByFilter(@PathVariable String filter) {
		try {
			return ResponseEntity.ok(bookingService.getUserBookingsByFilter(filter));
		} catch (Exception e) {
			return ResponseEntity.badRequest().build();
		}
	}

	@PostMapping("/{id}/return")
	public ResponseEntity<?> markAsReturned(@PathVariable Long id, @RequestBody Map<String, Object> request) {
		try {
			Double extraCharges = request.get("extraCharges") != null
					? Double.valueOf(request.get("extraCharges").toString())
					: 0.0;
			String returnNotes = (String) request.get("returnNotes");

			BookingResponse booking = bookingService.markAsReturned(id, extraCharges, returnNotes);
			return ResponseEntity.ok(booking);
		} catch (Exception e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

	@GetMapping("/active")
	public ResponseEntity<List<BookingResponse>> getActiveBookings() {
		return ResponseEntity.ok(bookingService.getActiveBookings());
	}

	@GetMapping("/overdue")
	public ResponseEntity<List<BookingResponse>> getOverdueBookings() {
		return ResponseEntity.ok(bookingService.getOverdueBookings());
	}

	@PostMapping("/{id}/mark-paid")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<BookingResponse> markAsPaid(@PathVariable Long id) {
		try {
			Booking booking = bookingRepository.findById(id).orElseThrow(() -> new BookingNotFoundException(id));

			if (booking.getStatus() == Booking.BookingStatus.CANCELLED) {
				throw new RuntimeException("Cannot mark cancelled booking as paid");
			}

			booking.setPaymentStatus("PAID");
			Booking savedBooking = bookingRepository.save(booking);

			try {
				emailService.sendPaymentConfirmation(booking.getUser(), savedBooking);
				System.out.println("Payment confirmation email sent for booking: " + booking.getId());
			} catch (Exception e) {
				System.err.println("Failed to send payment email: " + e.getMessage());
			}

			double discount = savedBooking.getDiscountAmount() != null ? savedBooking.getDiscountAmount() : 0.0;

			return ResponseEntity.ok(bookingService.convertToResponse(savedBooking, discount));

		} catch (Exception e) {
			System.err.println(" Error marking booking as paid: " + e.getMessage());
			return ResponseEntity.badRequest().body(null);
		}
	}

	@PostMapping("/{id}/extend")
	public ResponseEntity<?> extendBooking(@PathVariable Long id, @RequestBody Map<String, String> request) {
		try {
			String newEndDateStr = request.get("newEndDate");
			LocalDateTime newEndDate = LocalDateTime.parse(newEndDateStr);

			BookingResponse extendedBooking = bookingService.extendBooking(id, newEndDate);
			return ResponseEntity.ok(extendedBooking);
		} catch (Exception e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

	@PostMapping("/{id}/pickup")
	public ResponseEntity<?> markAsPickedUp(@PathVariable Long id, @RequestBody Map<String, String> request) {
		try {
			String pickupNotes = request.get("pickupNotes");
			BookingResponse booking = bookingService.markAsPickedUp(id, pickupNotes);
			return ResponseEntity.ok(booking);
		} catch (Exception e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

}