package com.webshield.config;

import javafx.fxml.FXMLLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;

import java.net.URL;

/**
 * Bridge between the JavaFX UI runtime and the Spring Boot ApplicationContext.
 * Facilitates dependency injection into JavaFX controllers and manages lifecycle shutdown.
 */
public final class SpringContext {

    private static final Logger log = LoggerFactory.getLogger(SpringContext.class);

    private static ConfigurableApplicationContext applicationContext;

    private SpringContext() {}

    public static synchronized void setApplicationContext(ConfigurableApplicationContext context) {
        applicationContext = context;
        log.info("Spring ApplicationContext registered with SpringContext bridge.");
    }

    public static synchronized ConfigurableApplicationContext getApplicationContext() {
        return applicationContext;
    }

    /**
     * Retrieves a Spring-managed bean by class, or null if context is not yet loaded.
     */
    public static <T> T getBean(Class<T> beanClass) {
        if (applicationContext != null && applicationContext.isActive()) {
            try {
                return applicationContext.getBean(beanClass);
            } catch (Exception e) {
                log.debug("Bean not found in Spring context: {}, instantiating directly.", beanClass.getSimpleName());
            }
        }
        return null;
    }

    /**
     * Creates an {@link FXMLLoader} that resolves controllers via Spring's ApplicationContext.
     * If a controller is not managed by Spring, falls back to standard reflection instantiation.
     */
    public static FXMLLoader createLoader(URL fxmlUrl) {
        FXMLLoader loader = new FXMLLoader(fxmlUrl);
        loader.setControllerFactory(controllerClass -> {
            T: {
                if (applicationContext != null && applicationContext.isActive()) {
                    try {
                        return applicationContext.getBean(controllerClass);
                    } catch (Exception ignored) {
                        // Fall back to reflection
                    }
                }
            }
            try {
                return controllerClass.getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                log.error("Failed to instantiate controller: {}", controllerClass.getName(), e);
                throw new IllegalStateException("Could not create controller for: " + controllerClass.getName(), e);
            }
        });
        return loader;
    }

    /**
     * Gracefully closes the Spring ApplicationContext.
     */
    public static synchronized void close() {
        if (applicationContext != null && applicationContext.isActive()) {
            log.info("Closing Spring ApplicationContext...");
            applicationContext.close();
            applicationContext = null;
        }
    }
}

