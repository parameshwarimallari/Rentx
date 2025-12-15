package com.rentx.carrental.validation;

import com.rentx.carrental.util.SqlInjectionProtectionUtil;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import jakarta.validation.Constraint;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = NoSqlInjection.NoSqlInjectionValidator.class)
@Documented
public @interface NoSqlInjection {
    
    String message() default "Input contains potential SQL injection";
    
    Class<?>[] groups() default {};
    
    Class<?>[] payload() default {};
    
    class NoSqlInjectionValidator implements ConstraintValidator<NoSqlInjection, String> {
        
        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null || value.trim().isEmpty()) {
                return true;
            }
            return !SqlInjectionProtectionUtil.containsSqlInjection(value);
        }
    }
}