package com.rentx.carrental.dto;

import com.rentx.carrental.validation.NoSqlInjection;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    
    @NotBlank(message = "Username is required")
    @NoSqlInjection
    private String username;
    
    @NotBlank(message = "Password is required")
    private String password;
}