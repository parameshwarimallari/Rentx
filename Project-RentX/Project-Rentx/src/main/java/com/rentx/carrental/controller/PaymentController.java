package com.rentx.carrental.controller;

import com.rentx.carrental.service.PaymentService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class PaymentController {

	private final PaymentService paymentService;

	@Value("${razorpay.key.id}")
	private String razorpayKeyId;

	@PostMapping("/create-order")
	public ResponseEntity<?> createOrder(@RequestBody Map<String, Object> request) {
		try {
			Long bookingId = Long.valueOf(request.get("bookingId").toString());
			Double amount = Double.valueOf(request.get("amount").toString());

			String order = paymentService.createOrder(bookingId, amount);
			return ResponseEntity.ok(order);
		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Error creating order: " + e.getMessage());
		}
	}

	@GetMapping("/config")
	public ResponseEntity<?> getRazorpayConfig() {
		try {
			Map<String, String> config = new HashMap<>();
			config.put("key", razorpayKeyId);
			config.put("currency", "INR");

			return ResponseEntity.ok(config);
		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Error getting payment config: " + e.getMessage());
		}
	}

	@GetMapping("/booking/{bookingId}")
	public ResponseEntity<?> getPaymentByBooking(@PathVariable Long bookingId) {
		try {
			return ResponseEntity.ok().body("Payment details");
		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Error fetching payment details");
		}
	}

	@PostMapping("/verify")
	public ResponseEntity<?> verifyPayment(@RequestBody Map<String, String> request) {
		try {
			String razorpayOrderId = request.get("razorpay_order_id");
			String razorpayPaymentId = request.get("razorpay_payment_id");
			String razorpaySignature = request.get("razorpay_signature");

			System.out.println("Order ID: " + razorpayOrderId);
			System.out.println("Payment ID: " + razorpayPaymentId);

			boolean isVerified = paymentService.verifyPayment(razorpayOrderId, razorpayPaymentId, razorpaySignature);

			if (isVerified) {
				System.out.println("Payment verification successful");
				return ResponseEntity.ok().body("Payment verified successfully");
			} else {
				System.out.println("Payment verification failed");
				return ResponseEntity.badRequest().body("Payment verification failed");
			}
		} catch (Exception e) {
			System.err.println("Error in payment verification: " + e.getMessage());
			return ResponseEntity.badRequest().body("Error verifying payment: " + e.getMessage());
		}
	}
}