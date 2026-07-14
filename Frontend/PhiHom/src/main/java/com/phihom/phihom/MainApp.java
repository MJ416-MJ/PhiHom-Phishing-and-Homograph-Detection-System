package com.phihom.phihom;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

public class MainApp extends Application {

    private static Process flaskProcess;
    private Stage splashStage;
    private javafx.scene.layout.Region progressFill;
    private javafx.scene.control.Label percentLabel;
    private javafx.scene.control.Label statusLabel;
    private static final double BAR_WIDTH = 340;

    private void showSplash() {
        splashStage = new Stage();

        javafx.scene.layout.StackPane splashLayout = new javafx.scene.layout.StackPane();
        splashLayout.setStyle("-fx-background-color: #1a1a2e;");

        // Background logo image, filling the whole splash
        java.net.URL imgUrl = getClass().getResource("/com/phihom/phihom/logo.png");
        if (imgUrl != null) {
            javafx.scene.image.Image logo = new javafx.scene.image.Image(imgUrl.toExternalForm());
            javafx.scene.image.ImageView logoView = new javafx.scene.image.ImageView(logo);
            logoView.setPreserveRatio(false);
            logoView.setSmooth(true);
            logoView.fitWidthProperty().bind(splashLayout.widthProperty());
            logoView.fitHeightProperty().bind(splashLayout.heightProperty());
            splashLayout.getChildren().add(logoView);
        }

        // Dark gradient scrim behind the bottom bar
        javafx.scene.layout.Region scrim = new javafx.scene.layout.Region();
        scrim.setStyle(
                "-fx-background-color: linear-gradient(to bottom, rgba(0,0,0,0), rgba(0,0,0,0.75));"
        );
        scrim.setPrefHeight(140);
        javafx.scene.layout.StackPane.setAlignment(scrim, javafx.geometry.Pos.BOTTOM_CENTER);
        splashLayout.getChildren().add(scrim);

        // Foreground content: progress bar + percentage + status
        javafx.scene.layout.VBox overlay = new javafx.scene.layout.VBox(8);
        overlay.setAlignment(Pos.BOTTOM_CENTER);
        overlay.setStyle("-fx-padding: 0 40 30 40;");
        javafx.scene.layout.StackPane.setAlignment(overlay, javafx.geometry.Pos.BOTTOM_CENTER);

        javafx.scene.layout.HBox textRow = new javafx.scene.layout.HBox();
        textRow.setAlignment(javafx.geometry.Pos.CENTER);
        textRow.setPrefWidth(BAR_WIDTH);

        statusLabel = new javafx.scene.control.Label("Starting backend...");
        statusLabel.setStyle(
                "-fx-text-fill: #ffffff;" +
                        "-fx-font-size: 12;" +
                        "-fx-font-weight: bold;" +
                        "-fx-effect: dropshadow(gaussian, rgba(0,0,0,0.6), 4, 0.5, 0, 1);"
        );

        percentLabel = new javafx.scene.control.Label("1%");
        percentLabel.setStyle(
                "-fx-text-fill: #00c6ff;" +
                        "-fx-font-size: 12;" +
                        "-fx-font-weight: bold;" +
                        "-fx-effect: dropshadow(gaussian, rgba(0,0,0,0.6), 4, 0.5, 0, 1);"
        );

        javafx.scene.layout.Region spacer = new javafx.scene.layout.Region();
        javafx.scene.layout.HBox.setHgrow(spacer, javafx.scene.layout.Priority.ALWAYS);
        textRow.getChildren().addAll(statusLabel, spacer, percentLabel);

        javafx.scene.layout.StackPane barContainer = new javafx.scene.layout.StackPane();
        barContainer.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
        barContainer.setPrefWidth(BAR_WIDTH);
        barContainer.setMaxWidth(BAR_WIDTH);
        barContainer.setPrefHeight(8);
        barContainer.setStyle(
                "-fx-background-color: rgba(255,255,255,0.12);" +
                        "-fx-background-radius: 4;"
        );

        progressFill = new javafx.scene.layout.Region();
        progressFill.setPrefHeight(8);
        progressFill.setPrefWidth(BAR_WIDTH * 0.01); // start at 1%
        progressFill.setStyle(
                "-fx-background-color: linear-gradient(to right, #2563eb, #00c6ff);" +
                        "-fx-background-radius: 4;" +
                        "-fx-effect: dropshadow(gaussian, #2563eb, 8, 0.4, 0, 0);"
        );
        barContainer.getChildren().add(progressFill);

        overlay.getChildren().addAll(textRow, barContainer);
        splashLayout.getChildren().add(overlay);

        javafx.scene.Scene splashScene = new javafx.scene.Scene(splashLayout, 480, 300);
        splashStage.setScene(splashScene);
        splashStage.initStyle(javafx.stage.StageStyle.UNDECORATED);
        splashStage.centerOnScreen();
        splashStage.show();

        // Automatically animate progress from 1% to 100%
        animateSplashProgress();
    }

    /**
     * Animates the splash progress bar from 1% to 100% automatically,
     * updating the status text at key milestones. Runs entirely on the
     * JavaFX Application Thread via Timeline, so no extra threading needed.
     */
    private void animateSplashProgress() {
        javafx.animation.Timeline timeline = new javafx.animation.Timeline();
        timeline.setCycleCount(1);

        double totalSeconds = 4.0;

        for (int percent = 1; percent <= 100; percent++) {
            final int p = percent; // capture a fresh, effectively-final copy for the lambda
            double timeSeconds = (p / 100.0) * totalSeconds;
            double targetWidth = BAR_WIDTH * (p / 100.0);

            javafx.animation.KeyFrame frame = new javafx.animation.KeyFrame(
                    javafx.util.Duration.seconds(timeSeconds),
                    event -> {
                        percentLabel.setText(p + "%");
                        if (p < 30) {
                            statusLabel.setText("Starting backend...");
                        } else if (p < 70) {
                            statusLabel.setText("Connecting to Flask...");
                        } else if (p < 95) {
                            statusLabel.setText("Loading modules...");
                        } else {
                            statusLabel.setText("Ready!");
                        }
                    },
                    new javafx.animation.KeyValue(progressFill.prefWidthProperty(), targetWidth)
            );
            timeline.getKeyFrames().add(frame);
        }

        timeline.play();
    }

    private void hideSplash() {
        if (splashStage != null) {
            splashStage.close();
        }
    }

    @Override
    public void start(Stage stage) throws IOException {
        // Show splash screen first
        showSplash();

        // Start Flask in background thread
        new Thread(() -> {
            startFlask();

            // Once Flask is ready update UI on JavaFX thread
            Platform.runLater(() -> {
                hideSplash();

                try {
                    FXMLLoader fxmlLoader = new FXMLLoader(
                            MainApp.class.getResource("main-view.fxml")
                    );

                    Scene scene = new Scene(fxmlLoader.load(), 700, 500);

                    MainWindowController controller = fxmlLoader.getController();

                    stage.setTitle("PhiHom - Phishing Detection System");
                    stage.getIcons().add(new Image(
                            MainApp.class.getResourceAsStream("/com/phihom/phihom/icon.png")
                    ));

                    stage.setResizable(false);
                    stage.setScene(scene);

                    SystemTrayManager.init(stage);

                    stage.iconifiedProperty().addListener((observable, oldValue, minimized) -> {
                        if (minimized) {
                            controller.checkAnother();
                        }
                    });

                    stage.setOnHidden(e -> controller.checkAnother());

                    stage.setOnCloseRequest(event -> {
                        event.consume();
                        stage.hide();
                    });

                    stage.show();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }).start();

        Platform.setImplicitExit(false);
    }

    private static void startFlask() {
        try {

            String workingDir = System.getProperty("user.dir");
            System.out.println("Working dir: " + workingDir);
            File exe = new File(workingDir + File.separator + "app" + File.separator + "phihom-backend.exe");

            if (exe.exists()) {
                ProcessBuilder pb = new ProcessBuilder(exe.getAbsolutePath());
                pb.redirectErrorStream(true);
                flaskProcess = pb.start();
                new Thread(() -> {
                    try (BufferedReader br = new BufferedReader(
                            new InputStreamReader(flaskProcess.getInputStream()))) {

                        String line;
                        while ((line = br.readLine()) != null) {
                            System.out.println("[Backend] " + line);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }).start();

                Thread.sleep(3000);

                System.out.println("Alive: " + flaskProcess.isAlive());

                if (!flaskProcess.isAlive()) {
                    System.out.println("Exit code: " + flaskProcess.exitValue());
                }
                Thread.sleep(2000);
                System.out.println("Alive: " + flaskProcess.isAlive());
                System.out.println("Exit code: " +
                        (flaskProcess.isAlive() ? "still running" : flaskProcess.exitValue()));
                System.out.println("Flask backend started successfully");
            } else {
                System.out.println("Flask executable not found at: " + exe.getAbsolutePath());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void stopFlask() {
        if (flaskProcess != null && flaskProcess.isAlive()) {
            // Kill all child processes first
            flaskProcess.descendants().forEach(ph -> {
                ph.destroyForcibly();
            });
            // Then kill parent
            flaskProcess.destroyForcibly();
            try {
                flaskProcess.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}
            System.out.println("Flask backend stopped");
        }
        flaskProcess = null;
    }

    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(MainApp::stopFlask));
        launch();
    }
}