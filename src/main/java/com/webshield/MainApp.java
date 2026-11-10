package com.webshield;

import com.webshield.config.SpringContext;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.net.URL;

/**
 * JavaFX Application entry point for WebShield integrated with the Spring Boot ApplicationContext.
 *
 * <p>Initializes the Spring container in {@link #init()}, configures Spring-aware
 * controller dependency injection for JavaFX FXML loaders, and shuts down the container in {@link #stop()}.</p>
 */
public class MainApp extends Application {

    private static final Logger log = LoggerFactory.getLogger(MainApp.class);

    private static final String APP_TITLE = "WebShield – Security Assessment Platform";
    private static final double AUTH_W    = 820.0;
    private static final double AUTH_H    = 620.0;
    private static final double MIN_W     = 780.0;
    private static final double MIN_H     = 540.0;

    @Override
    public void init() throws Exception {
        log.info("Bootstrapping Spring Boot context for WebShield...");
        try {
            String[] args = getParameters() != null && getParameters().getRaw() != null
                    ? getParameters().getRaw().toArray(new String[0]) : new String[0];

            ConfigurableApplicationContext context = new SpringApplicationBuilder(WebShieldApplication.class)
                    .headless(false)
                    .web(WebApplicationType.NONE)
                    .run(args);

            SpringContext.setApplicationContext(context);
            log.info("Spring Boot context successfully initialized.");
        } catch (Exception e) {
            log.warn("Spring context initialization encountered warning/offline mode: {}", e.getMessage());
        }
    }

    @Override
    public void start(Stage stage) {
        log.info("Starting WebShield Desktop Application UI");
        try {
            URL fxmlUrl = getClass().getResource("/fxml/pages/login.fxml");
            if (fxmlUrl == null) {
                throw new IllegalStateException("Login layout not found: /fxml/pages/login.fxml");
            }

            FXMLLoader loader = SpringContext.createLoader(fxmlUrl);
            Parent root = loader.load();

            Scene scene = new Scene(root, AUTH_W, AUTH_H);

            URL cssUrl = getClass().getResource("/css/styles.css");
            if (cssUrl != null) {
                scene.getStylesheets().add(cssUrl.toExternalForm());
            } else {
                log.warn("Stylesheet not found: /css/styles.css");
            }

            stage.setTitle(APP_TITLE);
            stage.setScene(scene);
            stage.setMinWidth(MIN_W);
            stage.setMinHeight(MIN_H);
            stage.show();

            log.info("WebShield Login screen displayed");
        } catch (IOException e) {
            log.error("Application startup failed", e);
            throw new RuntimeException("UI initialisation failure", e);
        }
    }

    @Override
    public void stop() throws Exception {
        log.info("Shutting down WebShield application...");
        SpringContext.close();
        super.stop();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
