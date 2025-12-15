package com.rentx.carrental.service;

import com.rentx.carrental.dto.AuthResponse;
import com.rentx.carrental.dto.LoginRequest;
import com.rentx.carrental.dto.RegisterRequest;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.exception.EmailAlreadyExistsException;
import com.rentx.carrental.exception.UserAlreadyExistsException;
import com.rentx.carrental.repository.UserRepository;
import com.rentx.carrental.security.JwtTokenProvider;
import com.rentx.carrental.util.HtmlEscapeUtil;
import com.rentx.carrental.util.SqlInjectionProtectionUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        validateInputForSqlInjection(request);
        
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email is already taken!");
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username is already taken!");
        }

        User user = new User();
        user.setUsername(HtmlEscapeUtil.escapeHtmlAndLimit(request.getUsername(), 50));
        user.setEmail(HtmlEscapeUtil.escapeHtmlAndLimit(request.getEmail(), 100));
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(HtmlEscapeUtil.escapeHtmlAndLimit(request.getFirstName(), 50));
        user.setLastName(HtmlEscapeUtil.escapeHtmlAndLimit(request.getLastName(), 50));
        user.setPhoneNumber(HtmlEscapeUtil.escapeHtmlAndLimit(request.getPhoneNumber(), 20));
        user.setDriverLicense(HtmlEscapeUtil.escapeHtmlAndLimit(request.getDriverLicense(), 30));

        User savedUser = userRepository.save(user);

        String token = jwtTokenProvider.generateToken(savedUser.getUsername());

        return AuthResponse.builder()
                .token(token)
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .role(savedUser.getRole().name())
                .build();
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        if (SqlInjectionProtectionUtil.containsSqlInjection(request.getUsername())) {
            throw new RuntimeException("Invalid username format");
        }
        
        if (SqlInjectionProtectionUtil.containsSqlInjection(request.getPassword())) {
            throw new RuntimeException("Invalid password format");
        }
        
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        String token = jwtTokenProvider.generateToken(user.getUsername());

        return AuthResponse.builder()
                .token(token)
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }
    
    private void validateInputForSqlInjection(RegisterRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
        
        String[] fieldsToCheck = {
            request.getUsername(),
            request.getEmail(),
            request.getFirstName(),
            request.getLastName(),
            request.getPhoneNumber(),
            request.getDriverLicense()
        };
        
        for (String field : fieldsToCheck) {
            if (field != null && SqlInjectionProtectionUtil.containsSqlInjection(field)) {
                throw new IllegalArgumentException("Invalid input detected in registration fields");
            }
        }
    }
}