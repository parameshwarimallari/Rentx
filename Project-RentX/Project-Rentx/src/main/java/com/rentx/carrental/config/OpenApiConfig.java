package com.rentx.carrental.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
@Configuration
public class OpenApiConfig {
    
    @Bean
    public OpenAPI rentXOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("RentX Car Rental API")
                .description("""
                    Comprehensive car rental management system API. 
                    Features include user authentication, car booking, payment processing, 
                    loyalty programs, and admin management.
                    """)
                .version("v1.0.0")
                .contact(new Contact()
                    .name("RentX Support Team")
                    .email("support@rentx.com")
                    .url("https://rentx.com"))
                .license(new License()
                    .name("Apache 2.0")
                    .url("https://www.apache.org/licenses/LICENSE-2.0.html")))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
            .components(new Components()
                .addSecuritySchemes("bearerAuth",
                    new SecurityScheme()
                        .name("bearerAuth")
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("JWT token obtained from authentication endpoint")));
    }
}