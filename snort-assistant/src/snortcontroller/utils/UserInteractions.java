package snortcontroller.utils;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.layout.Region;

import java.util.Optional;

public class UserInteractions {
    public static Optional<ButtonType> showAlert(Alert.AlertType type, String content, ButtonType... buttons){
        Alert alert = new Alert(type, content, buttons);
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        return alert.showAndWait();
    }
}
