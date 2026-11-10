package com.webshield.api.mutation;

import com.webshield.api.models.ApiSchema;

import java.math.BigDecimal;
import java.util.List;
import java.util.Random;

/**
 * Numeric mutation operators providing unit increments/decrements, sign reversals,
 * boundary substitutions, out-of-bound shifts, overflow values, and floating-point edge cases.
 * Strictly respects Java numeric representations and constraints.
 */
public class NumericMutation {

    public static final List<Double> FLOATING_POINT_EDGES = List.of(
            -0.0,
            Double.NaN,
            Double.POSITIVE_INFINITY,
            Double.NEGATIVE_INFINITY,
            Double.MIN_VALUE,               // Smallest positive nonzero double: 4.9e-324
            Double.MIN_NORMAL,              // Smallest normal positive double: 2.225e-308
            Double.MAX_VALUE,               // Largest finite double: 1.797e+308
            1.0e-300,
            1.0e308
    );

    public static final List<Long> INTEGER_OVERFLOWS = List.of(
            (long) Integer.MAX_VALUE + 1L,   // 2147483648L
            (long) Integer.MIN_VALUE - 1L,   // -2147483649L
            Long.MAX_VALUE,                  // 9223372036854775807L
            Long.MIN_VALUE                   // -9223372036854775808L
    );

    /**
     * Increments the given number by 1 or 1.0.
     */
    public static Number increment(Number input) {
        if (input == null) return 1;
        if (input instanceof Double || input instanceof Float) {
            return input.doubleValue() + 1.0;
        }
        if (input instanceof Long) {
            return input.longValue() == Long.MAX_VALUE ? Long.MAX_VALUE : input.longValue() + 1L;
        }
        if (input instanceof BigDecimal bd) {
            return bd.add(BigDecimal.ONE);
        }
        if (input instanceof Integer) {
            if (input.intValue() == Integer.MAX_VALUE) {
                return (long) Integer.MAX_VALUE + 1L;
            }
            return Integer.valueOf(input.intValue() + 1);
        }
        return input.longValue() >= Integer.MAX_VALUE ? input.longValue() + 1L : input.intValue() + 1;
    }

    /**
     * Decrements the given number by 1 or 1.0.
     */
    public static Number decrement(Number input) {
        if (input == null) return -1;
        if (input instanceof Double || input instanceof Float) {
            return input.doubleValue() - 1.0;
        }
        if (input instanceof Long) {
            return input.longValue() == Long.MIN_VALUE ? Long.MIN_VALUE : input.longValue() - 1L;
        }
        if (input instanceof BigDecimal bd) {
            return bd.subtract(BigDecimal.ONE);
        }
        if (input instanceof Integer) {
            if (input.intValue() == Integer.MIN_VALUE) {
                return (long) Integer.MIN_VALUE - 1L;
            }
            return Integer.valueOf(input.intValue() - 1);
        }
        return input.longValue() <= Integer.MIN_VALUE ? input.longValue() - 1L : input.intValue() - 1;
    }

    /**
     * Reverses the sign of the given number (+ to -, - to +).
     */
    public static Number signReversal(Number input) {
        if (input == null) return -1;
        if (input instanceof Double || input instanceof Float) {
            double val = input.doubleValue();
            return val == 0.0 ? -1.0 : -val;
        }
        if (input instanceof BigDecimal bd) {
            return bd.compareTo(BigDecimal.ZERO) == 0 ? BigDecimal.valueOf(-1) : bd.negate();
        }
        if (input instanceof Integer) {
            int val = input.intValue();
            return val == 0 ? -1 : -val;
        }
        long val = input.longValue();
        return val == 0 ? -1L : -val;
    }

    /**
     * Substitutes zero (0 or 0.0).
     */
    public static Number zeroValue(boolean isFloatingPoint) {
        return isFloatingPoint ? 0.0 : 0;
    }

    /**
     * Produces a guaranteed negative value.
     */
    public static Number negativeValue(Number input, boolean isFloatingPoint) {
        if (input == null) {
            return isFloatingPoint ? -1.0 : -1;
        }
        double d = input.doubleValue();
        if (d > 0) {
            return isFloatingPoint ? -d : -input.longValue();
        } else if (d == 0) {
            return isFloatingPoint ? -1.0 : -1;
        } else {
            return isFloatingPoint ? d - 100.0 : input.longValue() - 100L;
        }
    }

    /**
     * Replaces with exact schema min/max or Java type boundary.
     */
    public static Number boundaryMinMax(ApiSchema schema, boolean isFloatingPoint, Random random) {
        if (schema != null) {
            boolean pickMin = random == null || random.nextBoolean();
            if (pickMin && schema.getMinimum() != null) {
                return isFloatingPoint ? schema.getMinimum().doubleValue() : schema.getMinimum().longValue();
            } else if (!pickMin && schema.getMaximum() != null) {
                return isFloatingPoint ? schema.getMaximum().doubleValue() : schema.getMaximum().longValue();
            }
        }
        if (isFloatingPoint) {
            return (random != null && random.nextBoolean()) ? Double.MIN_VALUE : Double.MAX_VALUE;
        } else {
            return (random != null && random.nextBoolean()) ? Integer.MIN_VALUE : Integer.MAX_VALUE;
        }
    }

    /**
     * Generates a value immediately outside schema boundaries (min - 1 or max + 1).
     */
    public static Number outsideBounds(ApiSchema schema, boolean isFloatingPoint, Random random) {
        if (schema != null) {
            boolean testMin = (random == null || random.nextBoolean());
            if (testMin && schema.getMinimum() != null) {
                return isFloatingPoint
                        ? schema.getMinimum().doubleValue() - 1.0
                        : schema.getMinimum().longValue() - 1L;
            }
            if (!testMin && schema.getMaximum() != null) {
                return isFloatingPoint
                        ? schema.getMaximum().doubleValue() + 1.0
                        : schema.getMaximum().longValue() + 1L;
            }
        }
        // Fallback: below 0 or beyond integer max
        return (random != null && random.nextBoolean()) ? -1 : (long) Integer.MAX_VALUE + 10L;
    }

    /**
     * Produces integer or numeric overflow values.
     */
    public static Number overflowValue(boolean isFloatingPoint, Random random) {
        if (isFloatingPoint) {
            return Double.MAX_VALUE;
        }
        int idx = random != null ? random.nextInt(INTEGER_OVERFLOWS.size()) : 0;
        return INTEGER_OVERFLOWS.get(idx);
    }

    /**
     * Produces large numeric values.
     */
    public static Number largeValue(boolean isFloatingPoint) {
        return isFloatingPoint ? 1.0e30 : 999999999999999999L;
    }

    /**
     * Generates floating point edge cases (NaN, Infinity, -0.0, smallest normals).
     */
    public static Double floatingPointEdge(Random random) {
        int idx = random != null ? random.nextInt(FLOATING_POINT_EDGES.size()) : 0;
        return FLOATING_POINT_EDGES.get(idx);
    }

    /**
     * Schema-aware application of a numeric mutation operator.
     */
    public static Number apply(MutationOperatorType type, Number input, ApiSchema schema, Random random) {
        boolean isFloatingPoint = (input instanceof Double || input instanceof Float)
                || (schema != null && (schema.getFormat() != null && (schema.getFormat().equalsIgnoreCase("float") || schema.getFormat().equalsIgnoreCase("double"))));

        return switch (type) {
            case NUMERIC_INCREMENT -> increment(input);
            case NUMERIC_DECREMENT -> decrement(input);
            case NUMERIC_SIGN_REVERSAL -> signReversal(input);
            case NUMERIC_ZERO -> zeroValue(isFloatingPoint);
            case NUMERIC_NEGATIVE -> negativeValue(input, isFloatingPoint);
            case NUMERIC_BOUNDARY_MIN_MAX -> boundaryMinMax(schema, isFloatingPoint, random);
            case NUMERIC_OUTSIDE_BOUNDS -> outsideBounds(schema, isFloatingPoint, random);
            case NUMERIC_OVERFLOW -> overflowValue(isFloatingPoint, random);
            case NUMERIC_LARGE_VALUE -> largeValue(isFloatingPoint);
            case NUMERIC_FLOATING_POINT_EDGE -> floatingPointEdge(random);
            default -> input != null ? input : 0;
        };
    }
}
