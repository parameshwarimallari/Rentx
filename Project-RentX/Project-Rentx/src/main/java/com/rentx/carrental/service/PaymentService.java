package com.rentx.carrental.service;

import com.razorpay.Order;
import com.razorpay.RazorpayClient;
import com.razorpay.Refund;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Booking.RefundStatus;
import com.rentx.carrental.entity.Payment;
import com.rentx.carrental.exception.PaymentException;
import com.rentx.carrental.exception.PaymentVerificationException;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.HmacUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentService {

	private final RazorpayClient razorpayClient;
	private final PaymentRepository paymentRepository;
	private final BookingRepository bookingRepository;
	private final EmailService emailService;

	@Value("${razorpay.key.id:}")
	private String keyId;

	@Value("${razorpay.key.secret:}")
	private String keySecret;

	public String createOrder(Long bookingId, Double amount) {
		if (keyId == null || keyId.isEmpty() || keySecret == null || keySecret.isEmpty()) {
			throw new PaymentException("Payment gateway not configured properly");
		}

		try {
			Booking booking = bookingRepository.findById(bookingId)
					.orElseThrow(() -> new RuntimeException("Booking not found"));

			JSONObject orderRequest = new JSONObject();
			orderRequest.put("amount", Math.round(amount * 100));
			orderRequest.put("currency", "INR");
			orderRequest.put("receipt", "receipt_" + bookingId);
			orderRequest.put("payment_capture", 1);

			Order order = razorpayClient.orders.create(orderRequest);

			Payment payment = new Payment();
			payment.setPaymentId("pay_" + System.currentTimeMillis());
			payment.setBookingId(bookingId);
			payment.setAmount(amount);
			payment.setCurrency("INR");
			payment.setRazorpayOrderId(order.get("id"));
			payment.setStatus("CREATED");
			paymentRepository.save(payment);

			log.info("✅ Payment order created for booking {}: {}", bookingId, order.get("id"));

			return order.toString();

		} catch (Exception e) {
			log.error("❌ Failed to create payment order for booking {}: {}", bookingId, e.getMessage());
			throw new PaymentException("Failed to create payment order: " + e.getMessage(), e);
		}
	}

	public boolean verifyPayment(String razorpayOrderId, String razorpayPaymentId, String razorpaySignature) {
		if (keySecret == null || keySecret.isEmpty()) {
			throw new PaymentVerificationException("Payment gateway not configured");
		}

		try {
			String generatedSignature = HmacUtils.hmacSha256Hex(keySecret, razorpayOrderId + "|" + razorpayPaymentId);

			boolean isValid = generatedSignature.equals(razorpaySignature);

			if (isValid) {
				Payment payment = paymentRepository.findByRazorpayOrderId(razorpayOrderId)
						.orElseThrow(() -> new RuntimeException("Payment not found for order: " + razorpayOrderId));

				payment.setRazorpayPaymentId(razorpayPaymentId);
				payment.setRazorpaySignature(razorpaySignature);
				payment.setStatus("CAPTURED");
				paymentRepository.save(payment);

				Booking booking = bookingRepository.findById(payment.getBookingId()).orElseThrow(
						() -> new RuntimeException("Booking not found for payment: " + payment.getBookingId()));

				booking.setPaymentStatus("PAID");
				bookingRepository.save(booking);

				log.info("✅ Payment verified and booking status updated to PAID for booking: {}", booking.getId());

				try {
					emailService.sendBookingConfirmation(booking.getUser(), booking);
					log.info("✅ Payment confirmation email sent to: {}", booking.getUser().getEmail());
				} catch (Exception e) {
					log.error("❌ Failed to send payment confirmation email: {}", e.getMessage());
				}
			} else {
				log.error("❌ Payment signature verification failed for order: {}", razorpayOrderId);
			}

			return isValid;

		} catch (Exception e) {
			log.error("❌ Payment verification failed for order {}: {}", razorpayOrderId, e.getMessage());
			throw new PaymentVerificationException("Payment verification failed: " + e.getMessage(), e);
		}
	}

	public String processRefund(Booking booking, double refundAmount) {
		try {
			Payment payment = paymentRepository.findByBookingId(booking.getId()).orElseThrow(
					() -> new RuntimeException("Payment record not found for booking: " + booking.getId()));

			if (!"CAPTURED".equals(payment.getStatus())) {
				throw new PaymentException(
						"Cannot refund - payment not captured. Current status: " + payment.getStatus());
			}

			JSONObject refundRequest = new JSONObject();
			refundRequest.put("amount", Math.round(refundAmount * 100)); // Convert to paise
			refundRequest.put("speed", "normal");
			refundRequest.put("receipt", "refund_" + booking.getId());

			Refund refund = razorpayClient.payments.refund(payment.getRazorpayPaymentId(), refundRequest);

			payment.setRefundAmount(refundAmount);
			payment.setRefundId(refund.get("id"));
			payment.setRefundDate(LocalDateTime.now());
			payment.setStatus("REFUNDED");
			paymentRepository.save(payment);

			booking.setRefundStatus(RefundStatus.PROCESSED);
			bookingRepository.save(booking);

			log.info("Refund processed successfully for booking {}: {}", booking.getId(), refund.get("id"));
			return refund.get("id");

		} catch (Exception e) {
			log.error("Refund failed for booking {}: {}", booking.getId(), e.getMessage());

			booking.setRefundStatus(RefundStatus.FAILED);
			bookingRepository.save(booking);

			throw new PaymentException("Refund processing failed: " + e.getMessage(), e);
		}
	}

	public Optional<Payment> getPaymentByBookingId(Long bookingId) {
		return paymentRepository.findByBookingId(bookingId);
	}

	public boolean hasPaymentForBooking(Long bookingId) {
		return paymentRepository.findByBookingId(bookingId).isPresent();
	}
}