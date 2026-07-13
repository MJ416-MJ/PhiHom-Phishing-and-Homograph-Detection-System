package com.phihom.phihom;

import javafx.fxml.FXML;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.VBox;
import org.json.JSONArray;
import org.json.JSONObject;
import java.awt.Desktop;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class MainWindowController {

    @FXML private TextField urlInput;
    @FXML private Label clipboardStatus;
    @FXML private Label statusBar;
    @FXML private Button checkButton;

    @FXML private VBox progressPanel;
    @FXML private ProgressBar progressBar;

    @FXML private VBox safePanel;
    @FXML private Label safeUrlLabel;

    @FXML private ScrollPane dangerScrollPane;
    @FXML private VBox dangerPanel;
    @FXML private TextFlow suspiciousUrlFlow;
    @FXML private Label verdictLabel;
    @FXML private Label scoreLabel;
    @FXML private VBox indicatorsBox;
    @FXML private VBox suggestionBox;
    @FXML private Label suggestionLabel;
    @FXML private Button goToButton;

    private String suggestedUrl = "";
    private Thread analysisThread;

    @FXML
    public void initialize() {
        // Enter key listener
        urlInput.setOnKeyPressed(event -> {
            if (event.getCode() == KeyCode.ENTER) {
                checkUrl();
            }
        });

        // Clipboard monitoring
        ClipboardMonitor.start(url -> {
            javafx.application.Platform.runLater(() -> {
                javafx.stage.Stage stage = (javafx.stage.Stage) urlInput.getScene().getWindow();
                stage.show();
                stage.toFront();
                stage.requestFocus();
                urlInput.setText(url);
                checkUrl();
            });
        });
    }

    @FXML
    protected void checkUrl() {
        String url = urlInput.getText().trim();
        if (url.isEmpty()) {
            clipboardStatus.setText("Error: No URL entered");
            return;
        }

        showPanel("progress");
        checkButton.setDisable(true);

        analysisThread = new Thread(() -> {
            FlaskHttpClient client = new FlaskHttpClient();
            String result = client.analyse(url);
            javafx.application.Platform.runLater(() -> {
                checkButton.setDisable(false);
                showPanel("none");
                processResult(result, url);
            });
        });
        analysisThread.setDaemon(true);
        analysisThread.start();
    }

    private void processResult(String result, String url) {
        try {
            JSONObject json = new JSONObject(result);
            String verdict = json.getString("verdict");
            int score = json.getInt("score");

            if (verdict.equals("Legitimate")) {
                safeUrlLabel.setText(url);
                showPanel("safe");
            } else {
                indicatorsBox.getChildren().clear();
                JSONArray suspicious_indicator = json.has("indicators") ? json.getJSONArray("indicators") : new JSONArray();
                String highlight = json.optString("highlight", "");
                System.out.println("Highlight received: [" + highlight + "]");
                try {
                    highlightUrl(url, suspicious_indicator,highlight);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                if (verdict.equals("Dangerous")) {
                    verdictLabel.setText("Verdict: DANGEROUS");
                    verdictLabel.setStyle(
                            "-fx-text-fill: #dc2626; -fx-font-size: 14; -fx-font-weight: bold;");
                } else if (verdict.equals("Suspicious")) {
                    verdictLabel.setText("Verdict: SUSPICIOUS");
                    verdictLabel.setStyle(
                            "-fx-text-fill: #f97316; -fx-font-size: 14; -fx-font-weight: bold;");
                } else {
                    verdictLabel.setText("Verdict: " + verdict);
                    verdictLabel.setStyle(
                            "-fx-text-fill: #555; -fx-font-size: 14; -fx-font-weight: bold;");
                }

                scoreLabel.setText("Risk Score: " + score);

                if (json.has("indicators")) {
                    JSONArray indicators = json.getJSONArray("indicators");
                    for (int i = 0; i < indicators.length(); i++) {
                        Label indicator = new Label("✗ " + indicators.getString(i));
                        indicator.setStyle("-fx-text-fill: #dc2626; -fx-font-size: 12;");
                        indicator.setWrapText(true);
                        indicatorsBox.getChildren().add(indicator);
                    }
                }

                if (json.has("suggestion")) {
                    String suggestion = json.getString("suggestion");
                    suggestionLabel.setText("🔗 " + suggestion);
                    suggestedUrl = extractDomain(suggestion);
                    goToButton.setText("Go to " + suggestedUrl);
                    suggestionBox.setVisible(true);
                    suggestionBox.setManaged(true);
                } else {
                    suggestionBox.setVisible(false);
                    suggestionBox.setManaged(false);
                }

                if (json.has("Warning")) {
                    Label warning = new Label("⚠ " + json.getString("Warning"));
                    warning.setStyle("-fx-text-fill: #dc2626; -fx-font-weight: bold;");
                    warning.setWrapText(true);
                    indicatorsBox.getChildren().add(warning);
                }

                showPanel("danger");
            }
        } catch (Exception e) {
            clipboardStatus.setText("Error: " + "BAD URL");
        }
    }
    private void highlightUrl(String url, JSONArray suspicious_indicator,String extraHighlight) {
        suspiciousUrlFlow.getChildren().clear();

        List<String> suspiciousParts = new ArrayList<>();

        for (int i = 0; i < suspicious_indicator.length(); i++) {
            String indicator = suspicious_indicator.getString(i);

            if (indicator.startsWith("Keyword detected: ")) {
                suspiciousParts.add(
                        indicator.replace("Keyword detected: ", "").trim()
                );
            }

            else if (indicator.startsWith("Keywords detected: ")) {
                String words =
                        indicator.replace("Keywords detected: ", "").trim();

                for (String w : words.split(",")) {
                    suspiciousParts.add(w.trim());
                }
            }

            else if (indicator.startsWith("Insecure scheme detected: ")) {
                suspiciousParts.add(
                        indicator.replace("Insecure scheme detected: ", "").trim()
                );
            }

            else if (indicator.startsWith("Homograph detected: ")) {
                suspiciousParts.add(
                        indicator.replace("Homograph detected: ", "").trim()
                );
            }

            else if (indicator.startsWith("Possible homograph detected: ")) {
                suspiciousParts.add(
                        indicator.replace("Possible homograph detected: ", "").trim()
                );
            }
        }
        if (!extraHighlight.isEmpty()) {
            suspiciousParts.add(extraHighlight);
        }

        String lowerUrl = url.toLowerCase();

        int pos = 0;

        while (pos < url.length()) {
            int nearestIndex = -1;
            String nearestMatch = null;

            for (String part : suspiciousParts) {
                int idx = lowerUrl.indexOf(part.toLowerCase(), pos);

                if (idx >= 0 &&
                        (nearestIndex == -1 || idx < nearestIndex)) {
                    nearestIndex = idx;
                    nearestMatch = part;
                }
            }

            if (nearestIndex == -1) {
                Text normal = new Text(url.substring(pos));
                normal.setStyle("-fx-fill: #333;");
                suspiciousUrlFlow.getChildren().add(normal);
                break;
            }

            if (nearestIndex > pos) {
                Text normal =
                        new Text(url.substring(pos, nearestIndex));
                normal.setStyle("-fx-fill: #333;");
                suspiciousUrlFlow.getChildren().add(normal);
            }

            Text highlighted = new Text(
                    url.substring(
                            nearestIndex,
                            nearestIndex + nearestMatch.length()
                    )
            );

            highlighted.setStyle(
                    "-fx-fill: #dc2626; -fx-font-weight: bold;"
            );

            suspiciousUrlFlow.getChildren().add(highlighted);

            pos = nearestIndex + nearestMatch.length();
        }
    }

    private void showPanel(String panel) {
        progressPanel.setVisible(false);
        progressPanel.setManaged(false);
        safePanel.setVisible(false);
        safePanel.setManaged(false);
        dangerScrollPane.setVisible(false);
        dangerScrollPane.setManaged(false);

        switch (panel) {
            case "progress":
                progressPanel.setVisible(true);
                progressPanel.setManaged(true);
                break;
            case "safe":
                safePanel.setVisible(true);
                safePanel.setManaged(true);
                break;
            case "danger":
                dangerScrollPane.setVisible(true);
                dangerScrollPane.setManaged(true);
                break;
        }
    }

    @FXML
    public void cancelAnalysis() {
        if (analysisThread != null && analysisThread.isAlive()) {
            analysisThread.interrupt();
        }
        showPanel("none");
        checkButton.setDisable(false);
        clipboardStatus.setText(" Analysis cancelled");
    }

    @FXML
    public void checkAnother() {
        urlInput.clear();
        showPanel("none");
        clipboardStatus.setText(
                "● PhiHom is monitoring your clipboard for URLs...");
    }

    @FXML
    public void goToSuggested() {
        try {
            if (!suggestedUrl.isEmpty()) {
                Desktop.getDesktop().browse(new URI("https://" + suggestedUrl));
            }
        } catch (Exception e) {
            clipboardStatus.setText("Could not open browser");
        } finally {
            checkAnother(); // reset UI after navigating
        }
    }

    private String extractDomain(String suggestion) {
        if (suggestion.contains("visit ")) {
            String after = suggestion.substring(suggestion.indexOf("visit ") + 6);
            after = after.split("\\?")[0]; // cut off everything from "?" onward
            return after.trim();
        }
        return suggestion;
    }
}