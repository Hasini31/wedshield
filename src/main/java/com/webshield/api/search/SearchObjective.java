package com.webshield.api.search;

import java.io.Serializable;
import java.util.Objects;

/**
 * Represents an independent, measurable testing objective within the MIO search space.
 */
public class SearchObjective implements Serializable {

    private final String id;
    private final ObjectiveType type;
    private final String endpointIdentifier;
    private final String targetValue;
    private final String description;

    public SearchObjective(String id, ObjectiveType type, String endpointIdentifier, String targetValue, String description) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.type = Objects.requireNonNull(type, "type must not be null");
        this.endpointIdentifier = Objects.requireNonNull(endpointIdentifier, "endpointIdentifier must not be null");
        this.targetValue = targetValue != null ? targetValue : "";
        this.description = description != null ? description : "";
    }

    public static SearchObjective forEndpoint(String endpointIdentifier) {
        String id = "OBJ:ENDPOINT:" + endpointIdentifier;
        return new SearchObjective(id, ObjectiveType.ENDPOINT_REACHED, endpointIdentifier, "",
                "Reach target endpoint " + endpointIdentifier);
    }

    public static SearchObjective forStatusCode(String endpointIdentifier, int statusCode) {
        String id = "OBJ:STATUS:" + endpointIdentifier + ":" + statusCode;
        return new SearchObjective(id, ObjectiveType.STATUS_CODE, endpointIdentifier, String.valueOf(statusCode),
                "Discover HTTP status code " + statusCode + " for endpoint " + endpointIdentifier);
    }

    public static SearchObjective forBoundary(String endpointIdentifier, String propertyOrParam, String boundaryType) {
        String id = "OBJ:BOUNDARY:" + endpointIdentifier + ":" + propertyOrParam + ":" + boundaryType;
        return new SearchObjective(id, ObjectiveType.BOUNDARY_EXERCISED, endpointIdentifier, propertyOrParam + "=" + boundaryType,
                "Exercise boundary condition '" + boundaryType + "' on property '" + propertyOrParam + "' for " + endpointIdentifier);
    }

    public static SearchObjective forValidation(String endpointIdentifier, String propertyOrError) {
        String id = "OBJ:VALIDATION:" + endpointIdentifier + ":" + propertyOrError;
        return new SearchObjective(id, ObjectiveType.VALIDATION_TRIGGERED, endpointIdentifier, propertyOrError,
                "Trigger input validation rejection for '" + propertyOrError + "' on " + endpointIdentifier);
    }

    public static SearchObjective forServerError(String endpointIdentifier) {
        String id = "OBJ:5XX:" + endpointIdentifier;
        return new SearchObjective(id, ObjectiveType.SERVER_ERROR, endpointIdentifier, "5xx",
                "Discover an unhandled 5xx server-side error on " + endpointIdentifier);
    }

    public static SearchObjective forResponseBehavior(String endpointIdentifier, String behaviorKey) {
        String id = "OBJ:BEHAVIOR:" + endpointIdentifier + ":" + behaviorKey;
        return new SearchObjective(id, ObjectiveType.RESPONSE_BEHAVIOR, endpointIdentifier, behaviorKey,
                "Observe distinct response behavior '" + behaviorKey + "' on " + endpointIdentifier);
    }

    public String getId() {
        return id;
    }

    public ObjectiveType getType() {
        return type;
    }

    public String getEndpointIdentifier() {
        return endpointIdentifier;
    }

    public String getTargetValue() {
        return targetValue;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SearchObjective that = (SearchObjective) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }

    @Override
    public String toString() {
        return "SearchObjective{" +
                "id='" + id + '\'' +
                ", type=" + type +
                ", endpointIdentifier='" + endpointIdentifier + '\'' +
                ", targetValue='" + targetValue + '\'' +
                '}';
    }
}

