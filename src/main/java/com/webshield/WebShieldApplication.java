package com.webshield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Spring Boot application bootstrap and configuration class for WebShield.
 * Coordinates dependency injection, Spring Data JPA repositories, and service lifecycle.
 */
@SpringBootApplication
@EnableTransactionManagement
public class WebShieldApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebShieldApplication.class, args);
    }
}

