package com.webshield.api.models;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Top-level metadata extracted from an OpenAPI/Swagger document.
 */
public class OpenApiMetadata {

    private String title = "Untitled API";
    private String version = "1.0.0";
    private String description;
    private String openApiVersion = "3.0.0";
    private List<String> servers = new ArrayList<>();
    private List<String> tags = new ArrayList<>();

    public OpenApiMetadata() {
    }

    public OpenApiMetadata(String title, String version, String description,
                           String openApiVersion, List<String> servers, List<String> tags) {
        this.title = title != null ? title : "Untitled API";
        this.version = version != null ? version : "1.0.0";
        this.description = description;
        this.openApiVersion = openApiVersion != null ? openApiVersion : "3.0.0";
        this.servers = servers != null ? new ArrayList<>(servers) : new ArrayList<>();
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getOpenApiVersion() {
        return openApiVersion;
    }

    public void setOpenApiVersion(String openApiVersion) {
        this.openApiVersion = openApiVersion;
    }

    public List<String> getServers() {
        return Collections.unmodifiableList(servers);
    }

    public void setServers(List<String> servers) {
        this.servers = servers != null ? new ArrayList<>(servers) : new ArrayList<>();
    }

    public void addServer(String server) {
        if (server != null && !server.isBlank()) {
            this.servers.add(server.trim());
        }
    }

    public List<String> getTags() {
        return Collections.unmodifiableList(tags);
    }

    public void setTags(List<String> tags) {
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
    }

    public void addTag(String tag) {
        if (tag != null && !tag.isBlank()) {
            this.tags.add(tag.trim());
        }
    }

    @Override
    public String toString() {
        return "OpenApiMetadata{" +
                "title='" + title + '\'' +
                ", version='" + version + '\'' +
                ", openApiVersion='" + openApiVersion + '\'' +
                ", serversCount=" + servers.size() +
                '}';
    }
}

