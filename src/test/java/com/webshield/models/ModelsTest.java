package com.webshield.models;

import com.webshield.dashboard.ScanRow;
import com.webshield.dashboard.WebsiteRow;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Models and Row Data Transfer Object Tests")
class ModelsTest {

    @Test
    @DisplayName("User model getters and setters function correctly")
    void testUserModel() {
        LocalDateTime now = LocalDateTime.now();
        User user = new User();
        user.setId(7);
        user.setFullName("Test User");
        user.setEmail("user@example.com");
        user.setPasswordHash("hashed_string");
        user.setCreatedAt(now);
        user.setUpdatedAt(now);

        assertEquals(7, user.getId());
        assertEquals("Test User", user.getFullName());
        assertEquals("user@example.com", user.getEmail());
        assertEquals("hashed_string", user.getPasswordHash());
        assertEquals(now, user.getCreatedAt());
        assertEquals(now, user.getUpdatedAt());

        User parameterized = new User(8, "Another User", "another@example.com", "hash2", now, now);
        assertEquals(8, parameterized.getId());
        assertEquals("Another User", parameterized.getFullName());
    }

    @Test
    @DisplayName("WebsiteRow model getters function correctly")
    void testWebsiteRow() {
        WebsiteRow row = new WebsiteRow(1, "Target App", "https://app.test", "01 Jan 2026", "02 Jan 2026", "ACTIVE");
        assertEquals(1, row.getId());
        assertEquals("Target App", row.getName());
        assertEquals("https://app.test", row.getUrl());
        assertEquals("01 Jan 2026", row.getRegisteredAt());
        assertEquals("02 Jan 2026", row.getLastScan());
        assertEquals("ACTIVE", row.getStatus());
    }

    @Test
    @DisplayName("ScanRow model getters function correctly")
    void testScanRow() {
        ScanRow row = new ScanRow(5, "Target App", "03 Jan 2026 14:00", "COMPLETED", 3);
        assertEquals(5, row.getId());
        assertEquals("Target App", row.getWebsiteName());
        assertEquals("03 Jan 2026 14:00", row.getStartedAt());
        assertEquals("COMPLETED", row.getStatus());
        assertEquals(3, row.getFindingsCount());
    }
}

