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
import javafx.scene.control.CheckBox;
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
 * Controller for the Login page.
 * Delegates all auth logic to {@link AuthService}; only handles UI wiring here.
 */
@Component
@Scope("prototype")
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    @FXML private TextField     emailField;
    @FXML private PasswordField passwordField;
    @FXML private CheckBox      rememberMeCheck;
    @FXML private Label         messageLabel;

    private final AuthService authService;

    public LoginController() {
        this(com.webshield.config.SpringContext.getBean(AuthService.class));
    }

    public LoginController(AuthService authService) {
        this.authService = authService != null ? authService : new AuthService();
    }

    @FXML
    public void initialize() {
        log.debug("LoginController initialised");
    }

    @FXML
    private void handleLogin(ActionEvent event) {
        clearMessage();
        String email    = emailField.getText();
        String password = passwordField.getText();

        try {
            User user = authService.login(email, password);
            log.info("Login successful for: {}", user.getEmail());
            loadShell((Node) event.getSource());
        } catch (IllegalArgumentException e) {
            showError(e.getMessage());
        } catch (AuthException e) {
            // Do not distinguish between "email not found" and "bad password"
            showError("Invalid email or password. Please try again.");
        } catch (Exception e) {
            log.error("Unexpected login error", e);
            showError("Unable to connect to the database. Check your configuration.");
        }
    }

    @FXML
    private void goToRegister(ActionEvent event) {
        try {
            loadScene((Node) event.getSource(),
                    "/fxml/pages/register.fxml",
                    "WebShield – Create Account",
                    820, 640);
        } catch (IOException e) {
            showError("Could not open registration page.");
        }
    }

    /* ── private helpers ───────────────────────────────────────────── */

    private void loadShell(Node source) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/shell.fxml"));
            Parent root = loader.load();
            Scene scene = new Scene(root, 1220, 760);
            URL cssUrl = getClass().getResource("/css/styles.css");
            if (cssUrl != null) scene.getStylesheets().add(cssUrl.toExternalForm());
            Stage stage = (Stage) source.getScene().getWindow();
            stage.setScene(scene);
            stage.setMinWidth(960);
            stage.setMinHeight(620);
            stage.setTitle("WebShield – Security Assessment Platform");
        } catch (IOException e) {
            log.error("Failed to load shell", e);
            showError("Failed to load the main application.");
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
