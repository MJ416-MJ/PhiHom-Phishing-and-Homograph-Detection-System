package com.phihom.phihom;

import javafx.application.Platform;
import javafx.stage.Stage;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;

public class SystemTrayManager {

    public static void init(Stage stage) {
        if (!SystemTray.isSupported()) {
            System.out.println("System tray not supported");
            return;
        }

        Platform.runLater(() -> {
            try {
                // Load tray icon
                URL imageUrl = SystemTrayManager.class.getResource("/com/phihom/phihom/icon.png");
                Image image;
                if (imageUrl != null) {
                    image = Toolkit.getDefaultToolkit().getImage(imageUrl);
                } else {
                    // Fallback to default icon
                    image = Toolkit.getDefaultToolkit()
                            .createImage(new byte[0]);
                }

                SystemTray tray = SystemTray.getSystemTray();

                //Right-click popup menu
                PopupMenu popup = new PopupMenu();

                MenuItem showItem = new MenuItem("Show PhiHom");
                showItem.addActionListener(e -> Platform.runLater(stage::show));

                MenuItem hideItem = new MenuItem("Hide");
                hideItem.addActionListener(e -> Platform.runLater(stage::hide));

                MenuItem exitItem = new MenuItem("Exit");
                exitItem.addActionListener(e -> {
                    try {
                        tray.remove(tray.getTrayIcons()[0]);
                    } catch (Exception ignored) {}
                    MainApp.stopFlask();
                    Platform.exit();
                    System.exit(0);
                });

                popup.add(showItem);
                popup.add(hideItem);
                popup.addSeparator();
                popup.add(exitItem);

                TrayIcon trayIcon = new TrayIcon(image, "PhiHom - Phishing Detection", popup);
                trayIcon.setImageAutoSize(true);

                // Double click to show window
                trayIcon.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2) {
                            Platform.runLater(() -> {
                                stage.show();
                                stage.toFront();
                            });
                        }
                    }
                });

                tray.add(trayIcon);

            } catch (Exception e) {
                System.out.println("Tray error: " + e.getMessage());
            }
        });
    }
}