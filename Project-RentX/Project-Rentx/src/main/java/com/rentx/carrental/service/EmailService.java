package com.rentx.carrental.service;

import java.time.LocalDateTime;
import com.rentx.carrental.entity.Review;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.exception.EmailSendingException;
import com.rentx.carrental.repository.BookingRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class EmailService {

	private final JavaMailSender mailSender;
	private final BookingRepository bookingRepository;

	public void sendBookingConfirmation(User user, Booking booking) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Booking Confirmed - RentX Car Rental");
			message.setText(createBookingConfirmationContent(user, booking));

			mailSender.send(message);
			log.info("Booking confirmation email sent to: {}", user.getEmail());

		} catch (Exception e) {
			log.error("Failed to send email to {}: {}", user.getEmail(), e.getMessage());
			throw new EmailSendingException("Failed to send booking confirmation", user.getEmail(),
					"BOOKING_CONFIRMATION", "Booking Confirmed", "confirmation_template", e);
		}
	}

	public void sendBookingCancellation(User user, Booking booking) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Booking Cancelled - RentX Car Rental");
			message.setText(createCancellationContent(user, booking));

			mailSender.send(message);
			log.info("Cancellation email sent to: {}", user.getEmail());

		} catch (Exception e) {
			log.error("Failed to send cancellation email to {}: {}", user.getEmail(), e.getMessage());
		}
	}

	public void sendReviewConfirmation(User user, Review review) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Thank You for Your Review - RentX");
			message.setText(createReviewConfirmationContent(user, review));

			mailSender.send(message);
			System.out.println("Review confirmation email sent to: " + user.getEmail());
		} catch (Exception e) {
			System.err.println("Failed to send review email: " + e.getMessage());
		}
	}

	private String createReviewConfirmationContent(User user, Review review) {
		return String.format(
				"Dear %s %s,\n\n" + "⭐ THANK YOU FOR YOUR REVIEW!\n\n"
						+ "We appreciate you taking the time to share your experience with us.\n\n"
						+ "📋 REVIEW DETAILS:\n" + "• Car: %s %s\n" + "• Rating: %d/5 stars\n" + "• Comment: %s\n\n"
						+ "Your feedback helps us improve our service for all customers.\n\n"
						+ "We look forward to serving you again soon!\n\n" + "Best regards,\n" + "RentX Team 🚗",
				user.getFirstName(), user.getLastName(), review.getCar().getBrand(), review.getCar().getModel(),
				review.getRating(), review.getComment() != null ? review.getComment() : "No comment provided");
	}

	private String createBookingConfirmationContent(User user, Booking booking) {
		long durationDays = ChronoUnit.DAYS.between(booking.getStartDate(), booking.getEndDate());
		double discountAmount = booking.getDiscountAmount() != null ? booking.getDiscountAmount() : 0.0;

		String paymentMethod = "Pay at Pickup";
		String paymentInstructions = "";

		if (booking.getPaymentStatus() != null) {
			if (booking.getPaymentStatus().equals("PAID")) {
				paymentMethod = "Paid Online";
				paymentInstructions = "• Payment Status: ✅ Already Paid\n";
			} else if (booking.getPaymentStatus().equals("PAY_AT_PICKUP")) {
				paymentMethod = "Pay at Pickup";
				paymentInstructions = "• Payment Due: ₹" + booking.getTotalPrice() + " at pickup\n";
			} else if (booking.getPaymentStatus().equals("PENDING")) {
				paymentMethod = "Payment Pending";
				paymentInstructions = "• Payment: Please complete payment before pickup\n";
			}
		}

		return String.format("Dear %s %s,\n\n" + "🎉 YOUR BOOKING IS CONFIRMED!\n\n" + "📋 BOOKING DETAILS:\n"
				+ "• Booking ID: %s\n" + "• Vehicle: %s %s\n" + "• Pickup Date: %s\n" + "• Return Date: %s\n"
				+ "• Rental Duration: %d days\n" + "• Payment Method: %s\n" + "%s" + // Payment instructions
				"\n" + "💰 PRICE BREAKDOWN:\n" + "• Daily Rate: ₹%.2f\n" + "• Loyalty Discount: -₹%.2f\n"
				+ "• Total Amount: ₹%.2f\n\n" + "📍 PICKUP LOCATION:\n" + "RentX Main Office\n"
				+ "123 Car Rental Street\n" + "City, State 12345\n\n" + "📞 Contact: +1 (555) 123-RENT\n"
				+ "📧 Email: support@rentx.com\n\n" + "📝 IMPORTANT REMINDERS:\n"
				+ "• Bring your driver's license and payment card\n" + "• Security deposit may be required\n"
				+ "• Late returns incur additional charges\n\n" + "Thank you for choosing RentX! 🚗\n\n"
				+ "Best regards,\n" + "The RentX Team", user.getFirstName(), user.getLastName(),
				booking.getId() != null ? booking.getId().toString() : "N/A", booking.getCar().getBrand(),
				booking.getCar().getModel(), formatDate(booking.getStartDate()), formatDate(booking.getEndDate()),
				durationDays, paymentMethod, paymentInstructions, booking.getCar().getDailyRate(), discountAmount,
				booking.getTotalPrice());
	}

	private String createCancellationContent(User user, Booking booking) {
		double refundAmount = booking.getRefundAmount() != null ? booking.getRefundAmount() : 0.0;
		String cancellationReason = booking.getCancellationReason() != null ? booking.getCancellationReason()
				: "Not specified";

		String paymentMethod = "Pay at Pickup";
		if (booking.getPaymentStatus() != null) {
			if (booking.getPaymentStatus().equals("PAID")) {
				paymentMethod = "Paid Online";
			} else if (booking.getPaymentStatus().equals("PAY_AT_PICKUP")) {
				paymentMethod = "Pay at Pickup";
			} else if (booking.getPaymentStatus().equals("PENDING")) {
				paymentMethod = "Payment Pending";
			}
		}

		StringBuilder content = new StringBuilder();
		content.append(String.format(
				"Dear %s %s,\n\n" + "Your booking has been cancelled.\n\n" + "📋 CANCELLED BOOKING:\n"
						+ "• Booking ID: %s\n" + "• Car: %s %s\n" + "• Original Dates: %s to %s\n"
						+ "• Payment Method: %s\n" + "• Cancellation Reason: %s\n" + "• Total Amount: ₹%.2f\n",
				user.getFirstName(), user.getLastName(), booking.getId() != null ? booking.getId().toString() : "N/A",
				booking.getCar().getBrand(), booking.getCar().getModel(), formatDate(booking.getStartDate()),
				formatDate(booking.getEndDate()), paymentMethod, cancellationReason, booking.getTotalPrice()));

		if ("PAID".equals(booking.getPaymentStatus())) {
			if (refundAmount > 0) {
				content.append(String.format("• Refund Amount: ₹%.2f\n\n", refundAmount));
				content.append(
						"💰 Refund will be processed to your original payment method within 5-7 business days.\n\n");
			} else {
				content.append("• Refund Amount: ₹0.00\n\n");
				content.append("ℹ️  No refund applicable as per our cancellation policy.\n\n");
			}
		} else {
			content.append("• Refund Amount: ₹0.00\n\n");
			content.append("ℹ️  No payment was made, so no refund is applicable.\n\n");
		}

		content.append("We're sorry to see you go! If there's anything we can do to improve your experience,\n"
				+ "please don't hesitate to contact us.\n\n" + "We hope to see you again soon!\n\n" + "Best regards,\n"
				+ "RentX Team 🚗");

		return content.toString();
	}

	private String formatDate(LocalDateTime date) {
		try {
			return date.format(DateTimeFormatter.ofPattern("EEE, MMM dd, yyyy 'at' hh:mm a"));
		} catch (Exception e) {
			return date.toString();
		}
	}

	public void sendBookingReminder(User user, Booking booking) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Upcoming Rental Reminder - RentX Car Rental");
			message.setText(createReminderContent(user, booking));

			mailSender.send(message);
			log.info("Booking reminder email sent to: {}", user.getEmail());

		} catch (Exception e) {
			log.error("Failed to send reminder email to {}: {}", user.getEmail(), e.getMessage());
		}
	}

	private String createReminderContent(User user, Booking booking) {
		return String.format(
				"Dear %s %s,\n\n" + "This is a friendly reminder about your upcoming car rental.\n\n"
						+ "📋 RENTAL REMINDER:\n" + "• Car: %s %s\n" + "• Pickup: %s\n" + "• Return: %s\n"
						+ "• Total: $%.2f\n\n" + "📍 Pickup Location:\n" + "   RentX Main Office\n"
						+ "   123 Car Rental Street\n" + "   City, State 12345\n\n" + "📋 REQUIRED DOCUMENTS:\n"
						+ "• Valid driver's license\n" + "• Payment card used for booking\n"
						+ "• Proof of insurance (if applicable)\n\n" + "We look forward to serving you!\n\n"
						+ "Safe travels,\n" + "RentX Team 🚗",
				user.getFirstName(), user.getLastName(), booking.getCar().getBrand(), booking.getCar().getModel(),
				formatDate(booking.getStartDate()), formatDate(booking.getEndDate()), booking.getTotalPrice());
	}

	public void sendReturnConfirmation(User user, Booking booking) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());

			if (booking.getIsLateReturn() != null && booking.getIsLateReturn()) {
				message.setSubject("Car Returned - Late Return Fee Applied");
			} else {
				message.setSubject("Car Returned - RentX Rental");
			}

			message.setText(createReturnConfirmationContent(user, booking));

			mailSender.send(message);
			System.out.println("Return confirmation email sent to: " + user.getEmail());
		} catch (Exception e) {
			System.err.println("Failed to send return email: " + e.getMessage());
		}
	}

	private String createPickupConfirmationContent(User user, Booking booking) {
		return String.format(
				"Dear %s %s,\n\n" + "✅ YOUR CAR HAS BEEN PICKED UP!\n\n" + "📋 PICKUP DETAILS:\n" + "• Booking ID: %s\n"
						+ "• Car: %s %s\n" + "• Pickup Time: %s\n" + "• Expected Return: %s\n\n" + "📍 REMINDERS:\n"
						+ "• Please return the car on time to avoid late fees\n" + "• Keep the car in good condition\n"
						+ "• Contact us immediately for any issues\n\n" + "Enjoy your ride! 🚗\n\n" + "Best regards,\n"
						+ "RentX Team",
				user.getFirstName(), user.getLastName(), booking.getId(), booking.getCar().getBrand(),
				booking.getCar().getModel(), formatDate(LocalDateTime.now()), formatDate(booking.getEndDate()));
	}

	private String createReturnConfirmationContent(User user, Booking booking) {
		StringBuilder content = new StringBuilder();

		content.append(String.format(
				"Dear %s %s,\n\n" + "✅ YOUR CAR HAS BEEN RETURNED!\n\n" + "📋 RETURN DETAILS:\n" + "• Booking ID: %s\n"
						+ "• Car: %s %s\n" + "• Scheduled Return: %s\n" + "• Actual Return: %s\n",
				user.getFirstName(), user.getLastName(), booking.getId(), booking.getCar().getBrand(),
				booking.getCar().getModel(), formatDate(booking.getEndDate()),
				formatDate(booking.getActualReturnTime())));

		// ✅ ADD LATE PENALTY INFO
		if (booking.getIsLateReturn() != null && booking.getIsLateReturn()) {
			content.append(String.format("• ⏰ Late Return Fee: ₹%.2f\n" + "• Late Duration: %d hours\n\n",
					booking.getLateReturnPenalty(),
					ChronoUnit.HOURS.between(booking.getEndDate(), booking.getActualReturnTime())));
		} else {
			content.append("Late Return Fee: ₹0.00 (Returned on time)\n\n");
		}

		content.append(String.format(
				"💰 FINAL AMOUNT:\n" + "• Rental Charges: ₹%.2f\n" + "• Late Fee: ₹%.2f\n" + "• Total Amount: ₹%.2f\n\n"
						+ "Thank you for choosing RentX! 🙏\n\n" + "Best regards,\n" + "RentX Team",
				booking.getTotalPrice() - (booking.getLateReturnPenalty() != null ? booking.getLateReturnPenalty() : 0),
				booking.getLateReturnPenalty() != null ? booking.getLateReturnPenalty() : 0, booking.getTotalPrice()));

		return content.toString();
	}

	public void sendRefundProcessed(User user, Booking booking) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Refund Processed - RentX Car Rental");
			message.setText(createRefundProcessedContent(user, booking));

			mailSender.send(message);
			System.out.println("Refund processed email sent to: " + user.getEmail());

		} catch (Exception e) {
			System.err.println("Failed to send refund email to " + user.getEmail() + ": " + e.getMessage());
		}
	}

	public void sendRefundFailed(User user, Booking booking, String errorMessage) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Refund Failed - RentX Car Rental");
			message.setText(createRefundFailedContent(user, booking, errorMessage));

			mailSender.send(message);
			System.out.println("Refund failed email sent to: " + user.getEmail());

		} catch (Exception e) {
			System.err.println("Failed to send refund failure email: " + e.getMessage());
		}
	}

	private String createRefundProcessedContent(User user, Booking booking) {
		return String.format(
				"Dear %s %s,\n\n" + "💰 GREAT NEWS! Your refund has been processed successfully.\n\n"
						+ "📋 REFUND DETAILS:\n" + "• Booking ID: %s\n" + "• Car: %s %s\n" + "• Refund Amount: ₹%.2f\n"
						+ "• Processed Date: %s\n\n" + "💳 REFUND INFORMATION:\n"
						+ "• The amount will be credited to your original payment method\n"
						+ "• It may take 5-7 business days to reflect in your account\n"
						+ "• You will receive a confirmation from your bank/payment provider\n\n" + "📞 Need Help?\n"
						+ "Contact: +1 (555) 123-RENT\n" + "Email: support@rentx.com\n\n"
						+ "Thank you for choosing RentX!\n\n" + "Best regards,\n" + "RentX Team 🚗",
				user.getFirstName(), user.getLastName(), booking.getId(), booking.getCar().getBrand(),
				booking.getCar().getModel(), booking.getRefundAmount(),
				LocalDateTime.now().format(DateTimeFormatter.ofPattern("MMM dd, yyyy")));
	}

	private String createRefundFailedContent(User user, Booking booking, String errorMessage) {
		return String.format(
				"Dear %s %s,\n\n" + " We encountered an issue processing your refund.\n\n" + "📋 BOOKING DETAILS:\n"
						+ "• Booking ID: %s\n" + "• Car: %s %s\n" + "• Refund Amount: ₹%.2f\n" + "• Error: %s\n\n"
						+ "🔧 NEXT STEPS:\n" + "• Our team has been notified and is working on the issue\n"
						+ "• You don't need to take any action\n" + "• We will retry the refund automatically\n"
						+ "• If the issue persists, we will contact you for alternative solutions\n\n"
						+ "📞 Immediate Assistance:\n" + "Contact: +1 (555) 123-RENT\n" + "Email: support@rentx.com\n\n"
						+ "We apologize for the inconvenience.\n\n" + "Best regards,\n" + "RentX Team 🚗",
				user.getFirstName(), user.getLastName(), booking.getId(), booking.getCar().getBrand(),
				booking.getCar().getModel(), booking.getRefundAmount(), errorMessage);
	}

	public void sendPickupConfirmation(User user, Booking booking) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Car Picked Up - RentX Rental");
			message.setText(createPickupConfirmationContent(user, booking));

			mailSender.send(message);
			System.out.println("Pickup confirmation email sent to: " + user.getEmail());
		} catch (Exception e) {
			System.err.println("Failed to send pickup email: " + e.getMessage());
		}
	}

	public void sendAdminApprovalEmail(User user) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Admin Request Approved - RentX");
			message.setText(createAdminApprovalContent(user));

			mailSender.send(message);
			log.info("Admin approval email sent to: {}", user.getEmail());
		} catch (Exception e) {
			log.error("Failed to send admin approval email: {}", e.getMessage());
		}
	}

	private String createAdminApprovalContent(User user) {
		return String.format(
				"Dear %s %s,\n\n" + "🎉 GREAT NEWS! Your admin request has been approved!\n\n"
						+ "You now have administrator privileges in the RentX Car Rental system.\n\n"
						+ "🔧 ADMIN CAPABILITIES:\n" + "• Manage all bookings\n" + "• View system statistics\n"
						+ "• Process admin requests\n" + "• Manage car inventory\n\n"
						+ "Please login again to access the admin dashboard.\n\n" + "Best regards,\n" + "RentX Team 🚗",
				user.getFirstName(), user.getLastName());
	}

	public void sendPaymentConfirmation(User user, Booking booking) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Payment Received - RentX Car Rental");
			message.setText(createPaymentConfirmationContent(user, booking));

			mailSender.send(message);
			System.out.println("Payment confirmation email sent to: " + user.getEmail());
		} catch (Exception e) {
			System.err.println("Failed to send payment email: " + e.getMessage());
		}
	}

	private String createPaymentConfirmationContent(User user, Booking booking) {
		return String.format(
				"Dear %s %s,\n\n" + "✅ PAYMENT RECEIVED!\n\n" + "Your payment has been successfully processed.\n\n"
						+ "📋 PAYMENT DETAILS:\n" + "• Booking ID: %s\n" + "• Car: %s %s\n" + "• Payment Date: %s\n"
						+ "• Amount Paid: ₹%.2f\n\n" + "🚗 RENTAL DETAILS:\n" + "• Pickup: %s\n" + "• Return: %s\n"
						+ "• Duration: %d days\n\n" + "💳 PAYMENT METHOD:\n" + "• Paid at Pickup (Cash/Card)\n\n"
						+ "Thank you for your payment! Your booking is now fully confirmed.\n\n" + "Best regards,\n"
						+ "RentX Team 🚗",
				user.getFirstName(), user.getLastName(), booking.getId(), booking.getCar().getBrand(),
				booking.getCar().getModel(),
				LocalDateTime.now().format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' hh:mm a")),
				booking.getTotalPrice(), formatDate(booking.getStartDate()), formatDate(booking.getEndDate()),
				booking.getTotalDays());
	}

	@Scheduled(cron = "0 0 9 * * ?")
	public void sendBookingReminders() {
		LocalDateTime tomorrow = LocalDateTime.now().plusDays(1);
		List<Booking> tomorrowBookings = bookingRepository.findByStartDateBetween(tomorrow.withHour(0).withMinute(0),
				tomorrow.withHour(23).withMinute(59));

		for (Booking booking : tomorrowBookings) {
			sendBookingReminder(booking.getUser(), booking);
		}
	}

	public void sendPickupReminder(User user, Booking booking) {
		SimpleMailMessage message = new SimpleMailMessage();
		message.setTo(user.getEmail());
		message.setSubject("Pickup Reminder - Your Rental Starts Soon");
		message.setText(String.format(
				"Hi %s,\n\n" + "Just a reminder that your car rental pickup is in 1 hour:\n\n" + "🚗 Car: %s %s\n"
						+ "⏰ Pickup Time: %s\n" + "📍 Location: RentX Main Office\n\n"
						+ "Please bring your driver's license.\n\n" + "Need to cancel? Contact us immediately.\n\n"
						+ "Safe travels,\nRentX Team",
				user.getFirstName(), booking.getCar().getBrand(), booking.getCar().getModel(),
				formatDate(booking.getStartDate())));
		mailSender.send(message);
	}

	public void sendExtensionConfirmation(User user, Booking booking, double extensionCharge,
			LocalDateTime originalEndDate) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(user.getEmail());
			message.setSubject("Booking Extended - RentX Car Rental");
			message.setText(createExtensionContent(user, booking, extensionCharge, originalEndDate));

			mailSender.send(message);
			log.info("Extension confirmation email sent to: {}", user.getEmail());
		} catch (Exception e) {
			log.error("Failed to send extension email: {}", e.getMessage());
		}
	}

	private String createExtensionContent(User user, Booking booking, double extensionCharge,
			LocalDateTime originalEndDate) {
		long extraHours = ChronoUnit.HOURS.between(originalEndDate, booking.getEndDate());
		long extraDays = (extraHours + 23) / 24;

		return String.format("Dear %s %s,\n\n" + "✅ YOUR BOOKING HAS BEEN EXTENDED!\n\n" + "📋 EXTENSION DETAILS:\n"
				+ "• Booking ID: %s\n" + "• Car: %s %s\n" + "• Original Return: %s\n" + "• New Return: %s\n"
				+ "• Extension Period: %d extra day(s)\n" + "• Extension Charge: ₹%.2f\n\n" + "💰 UPDATED TOTAL:\n"
				+ "• Previous Total: ₹%.2f\n" + "• Extension Fee: +₹%.2f\n" + "• New Total: ₹%.2f\n\n"
				+ "📍 REMINDER:\n" + "• Return the car by the new return date\n"
				+ "• Late returns incur additional penalties\n" + "• Contact us if you need to extend further\n\n"
				+ "Thank you for choosing RentX!\n\n" + "Best regards,\n" + "RentX Team 🚗", user.getFirstName(),
				user.getLastName(), booking.getId(), booking.getCar().getBrand(), booking.getCar().getModel(),
				formatDate(originalEndDate), formatDate(booking.getEndDate()), extraDays, extensionCharge,
				booking.getTotalPrice() - extensionCharge, extensionCharge, booking.getTotalPrice());
	}

}