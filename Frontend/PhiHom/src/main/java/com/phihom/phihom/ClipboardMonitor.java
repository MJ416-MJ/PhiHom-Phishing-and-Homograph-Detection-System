package com.phihom.phihom;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.util.function.Consumer;
import java.util.concurrent.*;

public class ClipboardMonitor {

    private static String lastContent = "";
    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private static ScheduledFuture<?> pendingTask;

    public static void start(Consumer<String> onUrlDetected) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.addFlavorListener(event -> {
            // Cancel any pending check — a newer copy just happened
            if (pendingTask != null && !pendingTask.isDone()) {
                pendingTask.cancel(false);
            }
            // Wait briefly to let rapid copies settle, then process the latest one
            pendingTask = scheduler.schedule(() -> {
                try {
                    Clipboard cb = (Clipboard) event.getSource();
                    if (cb.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                        String content = getClipboardContent(cb);
                        if (content != null && !content.equals(lastContent) && isUrl(content)) {
                            lastContent = content;
                            onUrlDetected.accept(content);
                        }
                    }
                } catch (Exception e) {
                    System.out.println("Clipboard error: " + e.getMessage());
                }
            }, 50, TimeUnit.MILLISECONDS);
        });
    }

    private static String getClipboardContent(Clipboard cb) {
        int retries = 8;
        while (retries > 0) {
            try {
                return (String) cb.getData(DataFlavor.stringFlavor);
            } catch (Exception e) {
                retries--;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException ignored) {}
            }
        }
        return null;
    }

    private static boolean isUrl(String text) {
        return text != null &&
                (text.startsWith("http://") || text.startsWith("https://"));
    }
}