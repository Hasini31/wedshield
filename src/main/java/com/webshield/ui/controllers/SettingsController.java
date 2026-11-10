package com.webshield.ui.controllers;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * SettingsController manages user preferences, profile and password.
 *
 * <p>AuthService integration for password validation and update will be
 * wired in Stage 2 / Stage 8.</p>
 */
@Component
@Scope("prototype")
public class SettingsController {

    private static final Logger log = LoggerFactory.getLogger(SettingsController.class);

    @FXML private TextField     tfFullName;
    @FXML private TextField     tfEmail;
    @FXML private PasswordField pfCurrent;
    @FXML private PasswordField pfNew;
    @FXML private PasswordField pfConfirm;
    @FXML private Label         lblPasswordMsg;
    @FXML private Label         lblJavaVersion;

    @FXML
    public void initialize() {
        log.info("SettingsController initialised");
        if (lblJavaVersion != null) {
            lblJavaVersion.setText(System.getProperty("java.version") + " (Temurin)");
        }
    }

    @FXML
    private void onSaveProfile() {
        log.info("Save profile triggered – AuthService will be wired in Stage 2");
        // TODO: call UserRepository.updateProfile()
    }

    @FXML
    private void onChangePassword() {
        log.info("Change password triggered – AuthService will be wired in Stage 2");
        if (pfNew.getText().length() < 8) {
            lblPasswordMsg.setText("Password must be at least 8 characters.");
            return;
        }
        if (!pfNew.getText().equals(pfConfirm.getText())) {
            lblPasswordMsg.setText("New password and confirmation do not match.");
            return;
        }
        lblPasswordMsg.setText("Password update will be processed once auth is implemented.");
    }

    @FXML
    private void onLogout() {
        log.info("Logout triggered – session management will be wired in Stage 2");
        // TODO: call SessionManager.invalidateSession() and navigate to Login
    }
}

