package com.rentx.carrental.repository;

import com.rentx.carrental.entity.Car;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface CarRepository extends JpaRepository<Car, Long> {
    
    List<Car> findByAvailableTrue();
    List<Car> findByBrand(String brand);
    List<Car> findByCategory(Car.CarCategory category);
    List<Car> findByDailyRateLessThanEqual(Double maxRate);
    List<Car> findByBrandAndCategory(String brand, Car.CarCategory category);
    
    List<Car> findByBrandAndCategoryAndDailyRateLessThanEqual(String brand, Car.CarCategory category, Double maxRate);
    
    @Query("SELECT c FROM Car c WHERE c.available = true AND c.active = true")
    List<Car> findAvailableActiveCars();
    
    List<Car> findByActiveTrue();
    
    @Query("SELECT c FROM Car c WHERE c.available = true AND c.active = true " +
    	       "AND c.carId NOT IN (" +
    	       "SELECT b.car.carId FROM Booking b WHERE " +
    	       "b.status IN ('CONFIRMED', 'PENDING') " +
    	       "AND ((b.startDate <= :endDate AND b.endDate >= :startDate))" +
    	       ")")
    	List<Car> findAvailableCarsBetweenDates(@Param("startDate") LocalDateTime startDate, 
    	                                       @Param("endDate") LocalDateTime endDate);
	long countByAvailableTrue();
}
