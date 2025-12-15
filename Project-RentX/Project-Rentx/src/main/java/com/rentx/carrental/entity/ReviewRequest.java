package com.rentx.carrental.entity;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ReviewRequest {
    @NotNull
    private Long bookingId;
    
    @Min(1)
    @Max(5)
    private Integer rating;
    
    @Size(max = 500)
    private String comment;
}