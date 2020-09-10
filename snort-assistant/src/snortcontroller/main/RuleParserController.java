package snortcontroller.main;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.Callback;
import snortcontroller.utils.rules.Rule;
import snortcontroller.utils.rules.RuleParser;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class RuleParserController implements Initializable {
    // top toolbar components
    @FXML
    ToolBar topToolBar;
    @FXML
    TextField ruleFilePathTextField;
    @FXML
    Button findButton;
    @FXML
    Button openButton;

    // main components
    @FXML
    TableView<Rule> ruleTableView;

    // bottom toolbar components
    @FXML
    ToolBar bottomToolBar;
    @FXML
    Button saveButton;
    @FXML
    Button resetButton;

    RuleParser ruleParser;
    ArrayList<Rule> rules;
    ArrayList<Rule> editedRules;

    ExecutorService service = Executors.newSingleThreadExecutor();

    File ruleFile;
    final FileChooser fileChooser = new FileChooser();
    FileChooser.ExtensionFilter anyFilter = new FileChooser.ExtensionFilter("any file", "*.*");
    FileChooser.ExtensionFilter ruleFilter = new FileChooser.ExtensionFilter("snort rules", "*.rules");

    ContextMenu cellContextMenu;

    TableColumn<Rule, String> actionColumn;
    TableColumn<Rule, String> protocolColumn;
    TableColumn<Rule, String> sourceAddressColumn;
    TableColumn<Rule, String> sourcePortColumn;
    TableColumn<Rule, String> directionColumn;
    TableColumn<Rule, String> destinationAddressColumn;
    TableColumn<Rule, String> destinationPortColumn;
    TableColumn<Rule, String> optionBodyColumn;

    Stage optionBodyWindow = new Stage(StageStyle.DECORATED);
    VBox dialogContainer = new VBox(10);

    private Optional<ButtonType> showAlert(Alert.AlertType type, String content, ButtonType... buttons){
        Alert alert = new Alert(type, content, buttons);
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        return alert.showAndWait();
    }

    @FXML
    private void onClickFindButton(ActionEvent event){
        if (ruleFile != null){ // already opened log file
            fileChooser.setInitialDirectory(new File(ruleFile.getParent()));
        }
        File selectedFile = fileChooser.showOpenDialog(((Node)event.getSource()).getScene().getWindow());
        if (selectedFile != null){
            ruleFile = selectedFile;
            ruleFilePathTextField.setText(ruleFile.getAbsolutePath());
        }
    }

    @FXML
    private void onClickOpenButton(){
        if (ruleFilePathTextField.getText().isBlank() || ruleFile == null){
            showAlert(Alert.AlertType.ERROR, "Please specify rule files location");
            return;
        }

        if(!ruleFile.canRead()){
            showAlert(Alert.AlertType.ERROR, String.format("Cannot read specified rule file(%s). Try as root", ruleFilePathTextField.getText()));
            return;
        }

        ruleParser = new RuleParser(ruleFilePathTextField.getText());
        topToolBar.getItems().forEach(node -> node.setDisable(true));
        bottomToolBar.getItems().forEach(node -> node.setDisable(true));
        ruleTableView.setDisable(true);

        Runnable openFile = () -> {
            // TODO: visual element(loading circle?) to let user know program is loading rules
            try {
                ruleParser.parse();
                rules = ruleParser.getParsedRules();
                // TODO: optimization?
                rules.forEach(rule -> {
                    editedRules.add(rule.copy());
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
            ruleTableView.setItems(FXCollections.observableArrayList(editedRules));

            Platform.runLater(() -> {
                topToolBar.getItems().forEach(node -> node.setDisable(false));
                bottomToolBar.getItems().forEach(node -> node.setDisable(false));
                ruleTableView.setDisable(false);
            });
        };
        service.submit(openFile);
    }

    @FXML
    private void onClickSaveButton(){
        // TODO: save editedRules
    }

    @FXML
    private void onClickResetButton(){
        editedRules.clear();
        rules.forEach(rule -> {
            editedRules.add(rule.copy());
        });
        ruleTableView.setItems(FXCollections.observableArrayList(editedRules));
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // initialize container for storing edited rules
        editedRules = new ArrayList<>();

        // initialize window which will show option body elements.
        optionBodyWindow.initModality(Modality.APPLICATION_MODAL);
        optionBodyWindow.initOwner(null);
        optionBodyWindow.setAlwaysOnTop(true);
        dialogContainer.setPadding(new Insets(10.0, 10.0, 10.0, 10.0));
        dialogContainer.alignmentProperty().set(Pos.CENTER_LEFT);
        optionBodyWindow.setScene(new Scene(new ScrollPane(dialogContainer)));
        // TODO: edit and save feature to option elements?

        // initialize context menu for tableview
        cellContextMenu = new ContextMenu();
        MenuItem itemDeleteRow = new MenuItem("Delete this row");
        itemDeleteRow.setOnAction(onClickContextMenuDelete);
        cellContextMenu.getItems().addAll(itemDeleteRow);

        // set filter to file chooser
        fileChooser.getExtensionFilters().addAll(ruleFilter, anyFilter);

        // initialize table columns
        actionColumn = new TableColumn<>("Action");
        protocolColumn = new TableColumn<>("Protocol");
        sourceAddressColumn = new TableColumn<>("Source Address");
        sourcePortColumn = new TableColumn<>("Port");
        directionColumn = new TableColumn<>("Direction");
        destinationAddressColumn = new TableColumn<>("Destination Address");
        destinationPortColumn = new TableColumn<>("Port");
        optionBodyColumn = new TableColumn<>("Body");

        actionColumn.setMinWidth(80.0);
        protocolColumn.setMinWidth(80.0);
        sourceAddressColumn.setMinWidth(150.0);
        sourcePortColumn.setMinWidth(50.0);
        directionColumn.setMinWidth(80.0);
        destinationAddressColumn.setMinWidth(175.0);
        destinationPortColumn.setMinWidth(50.0);
        optionBodyColumn.setMinWidth(120.0);

        // read values from pcap log.
        actionColumn.setCellValueFactory(new PropertyValueFactory<>("ruleAction"));
        protocolColumn.setCellValueFactory(new PropertyValueFactory<>("ruleProtocol"));
        sourceAddressColumn.setCellValueFactory(new PropertyValueFactory<>("ruleSourceAddress"));
        sourcePortColumn.setCellValueFactory(new PropertyValueFactory<>("ruleSourcePort"));
        directionColumn.setCellValueFactory(new PropertyValueFactory<>("ruleDirection"));
        destinationAddressColumn.setCellValueFactory(new PropertyValueFactory<>("ruleDestinationAddress"));
        destinationPortColumn.setCellValueFactory(new PropertyValueFactory<>("ruleDestinationPort"));

        actionColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        protocolColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        sourceAddressColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        sourcePortColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        directionColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        destinationAddressColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        destinationPortColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        optionBodyColumn.setCellFactory(cellOptionBodyButtonFactory);

        // add columns to table and make it editable.
        ruleTableView.getColumns().addAll(actionColumn, protocolColumn, sourceAddressColumn, sourcePortColumn,
                directionColumn, destinationAddressColumn, destinationPortColumn, optionBodyColumn);
        // wait, wtf? you don't have to implement cell value factory with context menu! dang it.
        ruleTableView.setContextMenu(cellContextMenu);
        ruleTableView.itemsProperty().addListener(observable -> {
            ruleTableView.refresh();
        });
    }

    Callback<TableColumn<Rule, String>, TableCell<Rule, String>> cellOptionBodyButtonFactory = new Callback<>() {
        @Override
        public TableCell<Rule, String> call(TableColumn<Rule, String> param) {
            return new TextFieldTableCell<>() {
                final Button btn = new Button("Option Body");

                @Override
                public void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty) {
                        setGraphic(null);
                    } else {
                        btn.setOnAction(event -> {
                            Rule rule = this.getTableRow().getItem();
                            Map<String, String> ruleBodyElements = rule.getRuleBodyElements();
                            dialogContainer.getChildren().clear();
                            ruleBodyElements.forEach((key, value) -> {
                                Label optionName = new Label(key);
                                TextField optionValue = new TextField(value);
                                HBox container = new HBox(optionName, optionValue);

                                optionName.setMinWidth(80.0);
                                optionValue.setMinWidth(300.0);
                                HBox.setHgrow(optionName, Priority.ALWAYS);
                                HBox.setHgrow(optionValue, Priority.ALWAYS);
                                container.alignmentProperty().set(Pos.CENTER_LEFT);

                                dialogContainer.getChildren().add(container);
                            });
                            Button saveOptionButton = new Button("Save");
                            saveOptionButton.setOnAction(value -> {
                                Map<String, String> newRuleBodyElements = new HashMap<>();
                                dialogContainer.getChildren().forEach(container -> {
                                    Optional<String> optionName = Optional.empty();
                                    Optional<String> optionValue = Optional.empty();
                                    for(Node node: ((HBox)container).getChildren()) {
                                        if(node instanceof Label) {
                                            optionName = Optional.of(((Label)node).getText());
                                        } else if(node instanceof TextField) {
                                            optionValue = Optional.of(((TextField) node).getText());
                                        }
                                    }
                                    newRuleBodyElements.put(optionName.orElse("N/A"), optionValue.orElse("N/A"));
                                });
                                rule.setRuleBodyElements(newRuleBodyElements);

                            });
                            Button closeButton = new Button("Close");
                            closeButton.setOnAction(value -> {
                                ((Stage)((Node)value.getSource()).getScene().getWindow()).close();
                            });

                            dialogContainer.getChildren().add(new HBox(10, saveOptionButton, closeButton));
                            optionBodyWindow.show();
                        });
                        setGraphic(btn);
                    }
                    setText(null);
                }
            };
        }
    };

    EventHandler<ActionEvent> onClickContextMenuDelete = new EventHandler<ActionEvent>() {
        @Override
        public void handle(ActionEvent event) {
            MenuItem origin = (MenuItem) event.getSource();
            // Rule data = (Rule)origin.getParentPopup().getUserData();
            Rule data = ruleTableView.getSelectionModel().getSelectedItem();
            if(showAlert(Alert.AlertType.CONFIRMATION, "Delete this rule?", ButtonType.YES, ButtonType.NO).orElse(ButtonType.OK) == ButtonType.YES){
                ruleTableView.getItems().remove(data);
            }
        }
    };
}
