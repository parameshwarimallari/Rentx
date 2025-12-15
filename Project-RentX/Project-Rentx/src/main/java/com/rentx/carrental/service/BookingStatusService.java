package com.rentx.carrental.service;

import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Booking.BookingStatus;
import com.rentx.carrental.entity.Booking.RefundStatus;
import com.rentx.carrental.repository.BookingRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class BookingStatusService {
	private final PaymentService paymentService;
	private final BookingRepository bookingRepository;
	private final EmailService emailService;

	@Scheduled(fixedRate = 300000)
	public void updateBookingStatuses() {
		LocalDateTime now = LocalDateTime.now();

		List<Booking> toActivate = bookingRepository.findByStartDateBeforeAndStatus(now,
				Booking.BookingStatus.CONFIRMED);
		for (Booking booking : toActivate) {
			booking.setStatus(Booking.BookingStatus.ACTIVE);
			bookingRepository.save(booking);
			System.out.println("Booking " + booking.getId() + " set to ACTIVE");
		}

		List<Booking> toComplete = bookingRepository.findByEndDateBeforeAndStatus(now, Booking.BookingStatus.ACTIVE);
		for (Booking booking : toComplete) {
			booking.setStatus(Booking.BookingStatus.COMPLETED);
			bookingRepository.save(booking);
			System.out.println("Booking " + booking.getId() + " set to COMPLETED");
		}
	}

	@Scheduled(fixedRate = 3600000)
	public void updateRefundStatuses() {
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime sevenDaysAgo = now.minusDays(7);

		List<Booking> pendingRefunds = bookingRepository.findByStatusAndRefundStatusAndCancellationDateBefore(
				Booking.BookingStatus.CANCELLED, RefundStatus.PENDING, sevenDaysAgo);

		for (Booking booking : pendingRefunds) {
			try {
				if (booking.getRefundAmount() > 0 && "PAID".equals(booking.getPaymentStatus())) {
					paymentService.processRefund(booking, booking.getRefundAmount());
					System.out.println("Auto-processed refund for booking " + booking.getId());
				} else {
					booking.setRefundStatus(RefundStatus.PROCESSED);
					bookingRepository.save(booking);
					System.out.println("Marked refund as PROCESSED for payLater booking " + booking.getId());
				}
			} catch (Exception e) {
				System.err.println("Failed to process refund for booking " + booking.getId() + ": " + e.getMessage());
			}
		}
	}

	@Scheduled(cron = "0 0 1 * * ?")
	public void autoCancelUnconfirmedBookings() {
		LocalDateTime now = LocalDateTime.now();

		LocalDateTime twentyFourHoursAgo = now.minusHours(24);
		List<Booking> unpaidOnlineBookings = bookingRepository.findByStatusAndPaymentStatusAndBookingDateBefore(
				BookingStatus.CONFIRMED, "PENDING", twentyFourHoursAgo);

		for (Booking booking : unpaidOnlineBookings) {
			booking.setStatus(BookingStatus.CANCELLED);
			booking.setCancellationReason("Auto-cancelled: Online payment not completed within 24 hours");
			booking.setCancellationDate(now);
			bookingRepository.save(booking);
			emailService.sendBookingCancellation(booking.getUser(), booking);
		}

		LocalDateTime twoHoursAgo = now.minusHours(2);
		List<Booking> missedPickupBookings = bookingRepository
				.findByStatusAndPaymentStatusAndStartDateBefore(BookingStatus.CONFIRMED, "PAY_AT_PICKUP", twoHoursAgo);

		for (Booking booking : missedPickupBookings) {
			booking.setStatus(BookingStatus.CANCELLED);
			booking.setCancellationReason("Auto-cancelled: Customer didn't show up for pickup (2+ hours late)");
			booking.setCancellationDate(now);
			bookingRepository.save(booking);
			emailService.sendBookingCancellation(booking.getUser(), booking);
		}
	}
}