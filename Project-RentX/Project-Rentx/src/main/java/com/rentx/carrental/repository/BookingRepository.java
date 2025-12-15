package com.rentx.carrental.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Booking.BookingStatus;
import com.rentx.carrental.entity.Booking.PickupStatus;
import com.rentx.carrental.entity.Booking.RefundStatus;
import com.rentx.carrental.entity.User;

@Repository
public interface BookingRepository extends JpaRepository<Booking, Long> {
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car JOIN FETCH b.user WHERE b.user = :user ORDER BY b.bookingDate DESC")
    List<Booking> findByUserOrderByBookingDateDesc(@Param("user") User user);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.car.carId = :carId")
    List<Booking> findByCarCarId(@Param("carId") Long carId);
    
    @Query("SELECT b FROM Booking b WHERE b.car.carId = :carId " +
           "AND b.status IN ('CONFIRMED', 'PENDING') " +
           "AND ((b.startDate < :endDate AND b.endDate > :startDate))")
    List<Booking> findConflictingBookings(@Param("carId") Long carId, 
                                         @Param("startDate") LocalDateTime startDate,
                                         @Param("endDate") LocalDateTime endDate);
    
    long countByUserAndStatus(User user, Booking.BookingStatus status);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.startDate < :date AND b.status = :status")
    List<Booking> findByStartDateBeforeAndStatus(@Param("date") LocalDateTime date, 
                                                @Param("status") BookingStatus status);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.endDate < :date AND b.status = :status")
    List<Booking> findByEndDateBeforeAndStatus(@Param("date") LocalDateTime date, 
                                              @Param("status") BookingStatus status);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.user = :user AND b.status = :status ORDER BY b.bookingDate DESC")
    List<Booking> findByUserAndStatusOrderByBookingDateDesc(@Param("user") User user, 
                                                           @Param("status") BookingStatus status);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.user = :user AND b.endDate < :date ORDER BY b.bookingDate DESC")
    List<Booking> findByUserAndEndDateBeforeOrderByBookingDateDesc(@Param("user") User user, 
                                                                  @Param("date") LocalDateTime date);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.user = :user AND b.startDate > :date ORDER BY b.bookingDate DESC")
    List<Booking> findByUserAndStartDateAfterOrderByBookingDateDesc(@Param("user") User user, 
                                                                   @Param("date") LocalDateTime date);

    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.status = :status AND b.refundStatus = :refundStatus AND b.cancellationDate < :date")
    List<Booking> findByStatusAndRefundStatusAndCancellationDateBefore(@Param("status") BookingStatus status, 
                                                                      @Param("refundStatus") RefundStatus refundStatus,
                                                                      @Param("date") LocalDateTime date);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.refundStatus = :refundStatus")
    List<Booking> findByRefundStatus(@Param("refundStatus") RefundStatus refundStatus);
    
    long countByRefundStatus(RefundStatus refundStatus);

    @Query("SELECT COALESCE(SUM(b.refundAmount), 0.0) FROM Booking b WHERE b.refundStatus = :refundStatus")
    double sumRefundAmountByStatus(@Param("refundStatus") RefundStatus refundStatus);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.user = :user AND b.pickupStatus = :pickupStatus")
    List<Booking> findByUserAndPickupStatus(@Param("user") User user, 
                                           @Param("pickupStatus") PickupStatus pickupStatus);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.status = :status")
    List<Booking> findByStatus(@Param("status") BookingStatus status);
    
    @Query("SELECT b FROM Booking b JOIN FETCH b.car WHERE b.pickupStatus = :pickupStatus")
    List<Booking> findByPickupStatus(@Param("pickupStatus") PickupStatus pickupStatus);

	List<Booking> findByCarCarIdAndStatusIn(Long id, List<BookingStatus> asList);


	List<Booking> findByStatusAndPaymentStatusAndBookingDateBefore(BookingStatus confirmed, String string,
			LocalDateTime twentyFourHoursAgo);

	List<Booking> findByStatusAndPaymentStatusAndStartDateBefore(BookingStatus confirmed, String string,
			LocalDateTime twoHoursAgo);


	@Query("SELECT b FROM Booking b WHERE b.status = :status AND b.paymentMethodSelected = :paymentMethod AND b.paymentStatus = :paymentStatus AND b.bookingDate < :cutoffDate")
	List<Booking> findByStatusAndPaymentMethodSelectedAndPaymentStatusAndBookingDateBefore(
	    @Param("status") BookingStatus status,
	    @Param("paymentMethod") String paymentMethod,
	    @Param("paymentStatus") String paymentStatus,
	    @Param("cutoffDate") LocalDateTime cutoffDate
	);

	@Query("SELECT b FROM Booking b WHERE b.status = :status AND b.paymentMethodSelected = :paymentMethod AND b.startDate < :cutoffDate")
	List<Booking> findByStatusAndPaymentMethodSelectedAndStartDateBefore(
	    @Param("status") BookingStatus status,
	    @Param("paymentMethod") String paymentMethod,
	    @Param("cutoffDate") LocalDateTime cutoffDate
	);

	@Query("SELECT b FROM Booking b WHERE b.status = :status AND b.startDate < :cutoffDate")
	List<Booking> findByStatusAndStartDateBefore(
	    @Param("status") BookingStatus status,
	    @Param("cutoffDate") LocalDateTime cutoffDate
	);

	List<Booking> findByStartDateBetween(LocalDateTime withMinute, LocalDateTime withMinute2);

	@Query("SELECT b FROM Booking b WHERE b.car.carId = :carId " +
	       "AND ((b.startDate <= :endDate AND b.endDate >= :startDate)) " +
	       "AND b.status IN ('CONFIRMED', 'ACTIVE', 'PENDING')")
	List<Booking> findByCarCarIdAndDatesBetween(
	    @Param("carId") Long carId, 
	    @Param("startDate") LocalDateTime startDate,
	    @Param("endDate") LocalDateTime endDate
	);

	long countByStatus(BookingStatus confirmed);
	
	@Query("SELECT COALESCE(SUM(b.totalPrice), 0.0) FROM Booking b WHERE b.paymentStatus = 'PAID'")
	Double sumPaidRevenue();
}