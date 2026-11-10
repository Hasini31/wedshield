package com.webshield.ui.controllers;

import com.webshield.auth.AuthException;
import com.webshield.auth.AuthService;
import com.webshield.models.User;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * Controller for the Registration page.
 * Delegates all business logic to {@link AuthService}.
 */
@Component
@Scope("prototype")
public class RegisterController {

    private static final Logger log = LoggerFactory.getLogger(RegisterController.class);

    @FXML private TextField     fullNameField;
    @FXML private TextField     emailField;
    @FXML private PasswordField passwordField;
    @FXML private PasswordField confirmField;
    @FXML private Label         messageLabel;

    private final AuthService authService;

    public RegisterController() {
        this(com.webshield.config.SpringContext.getBean(AuthService.class));
    }

    public RegisterController(AuthService authService) {
        this.authService = authService != null ? authService : new AuthService();
    }

    @FXML
    public void initialize() {
        log.debug("RegisterController initialised");
    }

    @FXML
    private void handleRegister(ActionEvent event) {
        clearMessage();
        String fullName = fullNameField.getText();
        String email    = emailField.getText();
        String password = passwordField.getText();
        String confirm  = confirmField.getText();

        try {
            User user = authService.register(fullName, email, password, confirm);
            log.info("Registration successful for: {}", user.getEmail());
            // Navigate to login with a success hint
            goToLoginWithMessage((Node) event.getSource(),
                    "Account created! Please sign in.");
        } catch (IllegalArgumentException e) {
            showError(e.getMessage());
        } catch (AuthException e) {
            showError(e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected registration error", e);
            showError("Unable to connect to the database. Check your configuration.");
        }
    }

    @FXML
    private void goToLogin(ActionEvent event) {
        try {
            loadScene((Node) event.getSource(),
                    "/fxml/pages/login.fxml", "WebShield – Sign In", 820, 620);
        } catch (IOException e) {
            showError("Could not open login page.");
        }
    }

    /* ── private helpers ───────────────────────────────────────────── */

    private void goToLoginWithMessage(Node source, String message) {
        try {
            loadScene(source, "/fxml/pages/login.fxml",
                    "WebShield – Sign In", 820, 620);
        } catch (IOException e) {
            showError("Registration successful. Please return to the login page.");
        }
    }

    private void loadScene(Node source, String fxmlPath, String title,
                           double w, double h) throws IOException {
        FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource(fxmlPath));
        Parent root = loader.load();
        Scene scene = new Scene(root, w, h);
        URL cssUrl = getClass().getResource("/css/styles.css");
        if (cssUrl != null) scene.getStylesheets().add(cssUrl.toExternalForm());
        Stage stage = (Stage) source.getScene().getWindow();
        stage.setScene(scene);
        stage.setTitle(title);
    }

    private void showError(String msg) {
        messageLabel.setText(msg);
    }

    private void clearMessage() {
        messageLabel.setText("");
    }
}
