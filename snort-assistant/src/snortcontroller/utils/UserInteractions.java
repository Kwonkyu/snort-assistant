package snortcontroller.utils;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.layout.Region;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.util.Optional;

public class UserInteractions {
    public static Optional<ButtonType> showAlert(Alert.AlertType type, String content, ButtonType... buttons){
        Alert alert = new Alert(type, content, buttons);
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        return alert.showAndWait();
    }

    public static File openFile(Window window, String initialDirectory, FileChooser.ExtensionFilter... filters){
        final FileChooser fileChooser = new FileChooser();
        if(initialDirectory != null && new File(initialDirectory).exists()) fileChooser.setInitialDirectory(new File(initialDirectory));
        fileChooser.getExtensionFilters().clear();
        for (FileChooser.ExtensionFilter filter : filters) fileChooser.setSelectedExtensionFilter(filter);
        return fileChooser.showOpenDialog(window);
    }

    public static File saveFile(Window window, String initialDirectory, FileChooser.ExtensionFilter... filters){
        final FileChooser fileChooser = new FileChooser();
        if(initialDirectory != null && new File(initialDirectory).exists()) fileChooser.setInitialDirectory(new File(initialDirectory));
        fileChooser.getExtensionFilters().clear();
        for (FileChooser.ExtensionFilter filter : filters) fileChooser.setSelectedExtensionFilter(filter);
        return fileChooser.showSaveDialog(window);
    }

    public static File openDirectory(Window window){
        final DirectoryChooser directoryChooser = new DirectoryChooser();
        return directoryChooser.showDialog(window);
    }
}
