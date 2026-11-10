package com.webshield.ui.controllers;

import com.webshield.models.Website;
import com.webshield.website.WebsiteService;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * Controller for registering and editing authorized websites.
 */
@Component
@Scope("prototype")
public class AddWebsiteController {

    private static final Logger log = LoggerFactory.getLogger(AddWebsiteController.class);

    @FXML private Label lblDialogTitle;
    @FXML private TextField tfName;
    @FXML private TextField tfUrl;
    @FXML private TextArea taDescription;
    @FXML private CheckBox chkAuthorized;
    @FXML private Label lblError;
    @FXML private Button btnSave;

    private final WebsiteService websiteService;
    private Website editingWebsite;
    private Runnable onSaveCallback;

    public AddWebsiteController() {
        this(com.webshield.config.SpringContext.getBean(WebsiteService.class));
    }

    public AddWebsiteController(WebsiteService websiteService) {
        this.websiteService = websiteService != null ? websiteService : new WebsiteService();
    }

    @FXML
    public void initialize() {
        lblError.setText("");
    }

    public void setOnSaveCallback(Runnable callback) {
        this.onSaveCallback = callback;
    }

    public void setEditingWebsite(Website website) {
        this.editingWebsite = website;
        if (website != null) {
            lblDialogTitle.setText("Edit Registered Website");
            tfName.setText(website.getName());
            tfUrl.setText(website.getUrl());
            taDescription.setText(website.getDescription());
            chkAuthorized.setSelected(website.isAuthorized());
            btnSave.setText("Save Changes");
        }
    }

    @FXML
    private void onSave() {
        lblError.setText("");
        String name = tfName.getText();
        String url = tfUrl.getText();
        String description = taDescription.getText();
        boolean authorized = chkAuthorized.isSelected();

        try {
            if (editingWebsite == null) {
                websiteService.registerWebsite(name, url, description, authorized);
                log.info("Registered website: {}", url);
            } else {
                websiteService.updateWebsite(editingWebsite.getId(), name, url, description, authorized, editingWebsite.getStatus());
                log.info("Updated website: {}", url);
            }

            if (onSaveCallback != null) {
                onSaveCallback.run();
            }

            closeWindow();
        } catch (IllegalArgumentException e) {
            lblError.setText(e.getMessage());
        } catch (Exception e) {
            log.error("Failed to save website", e);
            lblError.setText("Error saving website. Please check database connection.");
        }
    }

    @FXML
    private void onCancel() {
        closeWindow();
    }

    private void closeWindow() {
        Stage stage = (Stage) tfName.getScene().getWindow();
        if (stage != null) {
            stage.close();
        }
    }
}

