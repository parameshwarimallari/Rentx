package com.rentx.carrental.service;

import java.time.LocalDateTime;
import java.util.List;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Car;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.CarRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AutoCancellationService {

	private final BookingRepository bookingRepository;
	private final EmailService emailService;
	private final CarRepository carRepository;

	@Scheduled(cron = "0 */30 * * * ?")
	public void autoCancelBookings() {
		LocalDateTime now = LocalDateTime.now();
		log.info("🔄 Running auto-cancellation at {}", now);

		cancelUnpaidOnlineBookings(now);

		cancelNoShowPickupBookings(now);

		cancelLastMinuteNoShows(now);
	}

	private void cancelUnpaidOnlineBookings(LocalDateTime now) {
		LocalDateTime twentyFourHoursAgo = now.minusHours(24);

		List<Booking> unpaidOnline = bookingRepository
				.findByStatusAndPaymentMethodSelectedAndPaymentStatusAndBookingDateBefore(
						Booking.BookingStatus.CONFIRMED, "PAY_NOW", "PENDING", twentyFourHoursAgo);

		for (Booking booking : unpaidOnline) {
			cancelBooking(booking, now, "Auto-cancelled: Online payment not completed within 24 hours");
			log.info("💰 Cancelled unpaid online booking {} (24h expired)", booking.getId());
		}
	}

	private void cancelNoShowPickupBookings(LocalDateTime now) {
		LocalDateTime twoHoursAfterPickup = now.minusHours(2);

		List<Booking> noShows = bookingRepository.findByStatusAndPaymentMethodSelectedAndStartDateBefore(
				Booking.BookingStatus.CONFIRMED, "PAY_AT_PICKUP", twoHoursAfterPickup);

		for (Booking booking : noShows) {
			cancelBooking(booking, now, "Auto-cancelled: Customer didn't show up for pickup (2+ hours late)");
			log.info("⏰ Cancelled no-show booking {} (2h late)", booking.getId());
		}
	}

	private void cancelLastMinuteNoShows(LocalDateTime now) {
		LocalDateTime oneHourBeforePickup = now.plusHours(1);

		List<Booking> lastMinute = bookingRepository.findByStatusAndStartDateBefore(Booking.BookingStatus.CONFIRMED,
				oneHourBeforePickup);

		for (Booking booking : lastMinute) {
			try {
				emailService.sendPickupReminder(booking.getUser(), booking);
				log.info("🔔 Sent pickup reminder for booking {}", booking.getId());
			} catch (Exception e) {
				log.error("Failed to send reminder: {}", e.getMessage());
			}
		}
	}

	private void cancelBooking(Booking booking, LocalDateTime now, String reason) {
		booking.setStatus(Booking.BookingStatus.CANCELLED);
		booking.setCancellationReason(reason);
		booking.setCancellationDate(now);

		Car car = booking.getCar();
		if (car != null) {
			car.setAvailable(true);
			carRepository.save(car);
			log.info("🚗 Freed up car {} after cancellation", car.getCarId());
		}

		bookingRepository.save(booking);

		try {
			emailService.sendBookingCancellation(booking.getUser(), booking);
		} catch (Exception e) {
			log.error("Failed to send cancellation email: {}", e.getMessage());
		}
	}
}