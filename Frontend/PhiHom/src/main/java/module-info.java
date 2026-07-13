module com.phihom.phihom {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.net.http;
    requires org.json;
    requires java.desktop;
    opens com.phihom.phihom to javafx.fxml;
    exports com.phihom.phihom;
}