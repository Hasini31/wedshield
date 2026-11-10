package com.webshield.api.service;

import com.webshield.api.models.SpecFormat;
import com.webshield.api.models.SpecType;

/**
 * Result of preliminary specification validation and inspection.
 */
public record SpecInspectionResult(
        SpecType specType,
        SpecFormat specFormat,
        int endpointsCount,
        String title,
        String version
) {
}

