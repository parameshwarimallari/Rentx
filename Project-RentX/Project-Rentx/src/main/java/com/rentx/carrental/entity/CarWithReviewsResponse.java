package com.rentx.carrental.entity;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CarWithReviewsResponse {
    private Car car;
    private List<Review> reviews;
    private Double averageRating;
    private Long reviewCount;
}
