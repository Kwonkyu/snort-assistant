package snortcontroller.main;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.chart.PieChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseButton;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.Callback;
import net.sourceforge.jpcap.util.HexHelper;
import snortcontroller.utils.pcap.PcapLog;
import snortcontroller.utils.pcap.PcapParser;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import static java.util.Collections.reverseOrder;

public class PcapParserController implements Initializable {
    // Toolbar components.
	@FXML
    TextField pcapFilePathTextField;
	@FXML
    Button findButton;
	@FXML
    Button openButton;
	@FXML
    Button updateChartButton;

	// Main components.
    @FXML
    ToolBar packetFilteringToolBar;
    @FXML
    Button applyFilterButton;
    @FXML
    Button clearFilterButton;
    @FXML
    ChoiceBox<FilterMode> filterModeChoiceBox;
	@FXML
    TableView<PcapLog> pcapLogTableView;
    @FXML
    PieChart pcapLogPieChart;

    // Side components.
    @FXML
    VBox pieChartControllerContainer;
    @FXML
    RadioButton sourceAddressRadioButton;
    @FXML
    RadioButton packetTypeRadioButton;
    @FXML
    RadioButton dateRadioButton;
    @FXML
    Spinner<Integer> chartThresholdSpinner;
    @FXML
    Label statusLabel;
    @FXML
    Label statisticsLabel;

    ExecutorService service = Executors.newSingleThreadExecutor();

    File pcapFile;
    final FileChooser fileChooser = new FileChooser();
    FileChooser.ExtensionFilter anyFilter = new FileChooser.ExtensionFilter("any file", "*.*");
    FileChooser.ExtensionFilter pcapFilter = new FileChooser.ExtensionFilter("libpcap formatted log", "*.pcap", "*.pcapng");

    PcapParser pcapParser;
    ArrayList<PcapLog> pcapLogs = new ArrayList<>();
    ArrayList<PcapLog> filteredLogs = new ArrayList<>();

    // MapProperty<FilterType, ArrayList<String>> logFilters;
    Map<FilterType, ArrayList<String>> logFilters = new HashMap<>();

    TableColumn<PcapLog, String> sourceAddressColumn;
    TableColumn<PcapLog, String> sourceHwAddressColumn;
    TableColumn<PcapLog, String> sourcePortColumn;
    TableColumn<PcapLog, String> destinationAddressColumn;
    TableColumn<PcapLog, String> destinationHwAddressColumn;
    TableColumn<PcapLog, String> destinationPortColumn;
    TableColumn<PcapLog, String> timevalColumn;
    TableColumn<PcapLog, String> protocolColumn;
    TableColumn<PcapLog, String> payloadColumn;

    Alert readUnavailableAlert = new Alert(Alert.AlertType.INFORMATION,"You're not able to read this file.");
    Stage payloadWindow = new Stage(StageStyle.DECORATED);
    TextArea headerTextArea, bodyTextArea;
    ContextMenu cellContextMenu;

    enum FilterMode { UNION("OR"), INTERSECTION("AND");
        String name;
        FilterMode(String s) { name = s; }
    }

    enum FilterType { SOURCEADDRESS("srcAddr"), DESTINATIONADDRESS("dstAddr"), PROTOCOL("pt");
        String name;
        FilterType(String s) {
            name = s;
        }
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // make vbox elements to grow vertically always
        VBox.setVgrow(pcapLogTableView, Priority.ALWAYS);
        VBox.setVgrow(pcapLogPieChart, Priority.ALWAYS);

        // initial filtering mode
        filterModeChoiceBox.getItems().addAll(FilterMode.INTERSECTION, FilterMode.UNION);
        filterModeChoiceBox.setValue(FilterMode.UNION);

        // initial filter list of each type
        logFilters.putIfAbsent(FilterType.SOURCEADDRESS, new ArrayList<>());
        logFilters.putIfAbsent(FilterType.DESTINATIONADDRESS, new ArrayList<>());
        logFilters.putIfAbsent(FilterType.PROTOCOL, new ArrayList<>());

        // Popup dialog to show payload
        payloadWindow.initModality(Modality.NONE);
        payloadWindow.initOwner(null);

        VBox headerContainer = new VBox(10);
        headerTextArea = new TextArea();
        headerContainer.getChildren().addAll(new Label("Header"), headerTextArea);

        VBox bodyContainer = new VBox(10);
        bodyTextArea = new TextArea();
        bodyContainer.getChildren().addAll(new Label("Body"), bodyTextArea);

        VBox dialogContainer = new VBox(20);
        dialogContainer.setPadding(new Insets(10.0, 10.0, 10.0, 10.0));
        dialogContainer.getChildren().addAll(headerContainer, bodyContainer);
        payloadWindow.setScene(new Scene(dialogContainer));

        // Adjust alert windows height to show all texts properly.
        readUnavailableAlert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);

        // 'Find' button to open file chooser window.
        fileChooser.getExtensionFilters().addAll(pcapFilter, anyFilter);

        // Context menu for right click on table cell
        cellContextMenu = new ContextMenu();
        MenuItem itemFilter = new MenuItem("Filter");
        itemFilter.setOnAction(onClickContextMenuFilter);
        MenuItem itemBlock = new MenuItem("Block");
        itemBlock.setOnAction(onClickContextMenuBlock);
        cellContextMenu.getItems().addAll(itemFilter, itemBlock);

        pcapLogTableView.setEditable(true);
        sourceAddressColumn = new TableColumn<>("Source Address");
        sourceHwAddressColumn = new TableColumn<>("Source MAC Address");
        sourcePortColumn = new TableColumn<>("Source Port");
        destinationAddressColumn = new TableColumn<>("Destination Address");
        destinationHwAddressColumn = new TableColumn<>("Destination MAC Address");
        destinationPortColumn = new TableColumn<>("Destination Port");
        timevalColumn = new TableColumn<>("Time");
        protocolColumn = new TableColumn<>("Protocol");
        payloadColumn = new TableColumn<>("Payload");

        // column layout settings.
        sourceAddressColumn.setMinWidth(150.0);
        sourceHwAddressColumn.setMinWidth(200.0);
        sourcePortColumn.setMinWidth(100.0);
        destinationAddressColumn.setMinWidth(175.0);
        destinationHwAddressColumn.setMinWidth(200.0);
        destinationPortColumn.setMinWidth(150.0);
        timevalColumn.setMinWidth(150.0);
        protocolColumn.setMinWidth(80.0);
        payloadColumn.setMinWidth(80.0);

        // read values from pcap log.
        sourceAddressColumn.setCellValueFactory(new PropertyValueFactory<>("sourceAddress"));
        sourceHwAddressColumn.setCellValueFactory(new PropertyValueFactory<>("sourceHwAddress"));
        sourcePortColumn.setCellValueFactory(new PropertyValueFactory<>("sourcePort"));
        destinationAddressColumn.setCellValueFactory(new PropertyValueFactory<>("destinationAddress"));
        destinationHwAddressColumn.setCellValueFactory(new PropertyValueFactory<>("destinationHwAddress"));
        destinationPortColumn.setCellValueFactory(new PropertyValueFactory<>("destinationPort"));
        timevalColumn.setCellValueFactory(new PropertyValueFactory<>("timeval"));
        protocolColumn.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        payloadColumn.setCellFactory(cellPayloadButtonFactory);

        // apply context menu factory to columns which has address to block or filter
        sourceAddressColumn.setCellFactory(cellContextMenuFactory);
        destinationAddressColumn.setCellFactory(cellContextMenuFactory);
        protocolColumn.setCellFactory(cellContextMenuFactory);

        pcapLogTableView.getColumns().addAll(timevalColumn, sourceAddressColumn, sourceHwAddressColumn, sourcePortColumn,
                destinationAddressColumn, destinationHwAddressColumn, destinationPortColumn, protocolColumn, payloadColumn);

        // PieChart threshold spinner initialization.
        chartThresholdSpinner.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, Integer.MAX_VALUE));
        chartThresholdSpinner.increment(9); // set initial value to 10.
    }

    private void updatePcapLogTableView(ArrayList<PcapLog> logs){
        pcapLogTableView.setItems(FXCollections.observableArrayList(logs));
        pcapLogTableView.refresh();
    }

    @FXML
    private void onClickApplyFilterButton(){
        // TODO: implement non-blocking with disabled elements when filtering logs.
        FilterMode filterMode = filterModeChoiceBox.getValue();
        ArrayList<String> filteredSourceAddresses = logFilters.get(FilterType.SOURCEADDRESS);
        ArrayList<String> filteredDestinationAddresses = logFilters.get(FilterType.DESTINATIONADDRESS);
        ArrayList<String> filteredProtocols = logFilters.get(FilterType.PROTOCOL);

        filteredLogs.clear();
        for(PcapLog pcapLog: pcapLogs){
            if(filterMode == FilterMode.INTERSECTION) {
                // intersection mode
                boolean isFiltered = true;
                if (!filteredSourceAddresses.isEmpty() && !filteredSourceAddresses.contains(pcapLog.getSourceAddress())) {
                    isFiltered = false;
                }
                if (!filteredDestinationAddresses.isEmpty() && !filteredDestinationAddresses.contains(pcapLog.getDestinationAddress())) {
                    isFiltered = false;
                }
                if (!filteredProtocols.isEmpty() && !filteredProtocols.contains(pcapLog.getProtocol())) {
                    isFiltered = false;
                }
                if (isFiltered) filteredLogs.add(pcapLog);
            }
            else if(filterMode == FilterMode.UNION) {
                // union mode
                if (filteredSourceAddresses.contains(pcapLog.getSourceAddress()) ||
                        filteredDestinationAddresses.contains(pcapLog.getDestinationAddress()) ||
                        filteredProtocols.contains(pcapLog.getProtocol())) {
                    filteredLogs.add(pcapLog);
                }
            }
        }
        updatePcapLogTableView(filteredLogs);
    }

    @FXML
    private void onClickClearFilterButton(){
        ArrayList<Node> deleteNodes = new ArrayList<>();
        packetFilteringToolBar.getItems().forEach(node -> {
            if(node instanceof CheckBox){
                deleteNodes.add(node);
            }
        });
        packetFilteringToolBar.getItems().removeAll(deleteNodes);

        logFilters.get(FilterType.SOURCEADDRESS).clear();
        logFilters.get(FilterType.DESTINATIONADDRESS).clear();
        logFilters.get(FilterType.PROTOCOL).clear();
        updatePcapLogTableView(pcapLogs);
    }

    @FXML
    private void onClickFindButton(ActionEvent event){
        if (pcapFile != null){ // already opened log file
            fileChooser.setInitialDirectory(new File(pcapFile.getParent()));
        }
        File selectedFile = fileChooser.showOpenDialog(((Node)event.getSource()).getScene().getWindow());
        if (selectedFile != null){
            pcapFile = selectedFile;
            pcapFilePathTextField.setText(pcapFile.getAbsolutePath());
        }
    }

    @FXML
    private void onClickOpenButton(){
        if (pcapFilePathTextField.getText().isBlank() || pcapFile == null){
            System.err.println("Please specify log file's location.");
            return;
        }

        if(!pcapFile.canRead()){
            readUnavailableAlert.show();
            return;
        }

        pcapParser = new PcapParser(pcapFilePathTextField.getText());
        statusLabel.setText("Status: LOADING");
        openButton.setDisable(true);
        packetFilteringToolBar.getItems().forEach(node -> node.setDisable(true));
        pieChartControllerContainer.getChildren().forEach(node -> node.setDisable(true));

        Runnable openFile = new Runnable() {
            @Override
            public void run() {
                try {
                    pcapParser.parse();
                    pcapLogs = pcapParser.getParsedPackets();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                pcapLogTableView.setItems(FXCollections.observableArrayList(pcapLogs));
                pcapLogTableView.refresh();

                Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        statusLabel.setText("Status: DONE");
                        statisticsLabel.setText(String.format("Packets: %d", pcapLogs.size()));
                        packetFilteringToolBar.getItems().forEach(node -> node.setDisable(false));
                        pieChartControllerContainer.getChildren().forEach(node -> node.setDisable(false));
                        openButton.setDisable(false);
                        updateChartButton.fire();
                    }
                });
            }
        };
        service.submit(openFile);
    }

    @FXML
    private void onClickUpdateChartButton(){
        pcapLogPieChart.getData().clear();
        Map<String, Integer> counter = new HashMap<>();

        // disable every element in container.
        pieChartControllerContainer.getChildren().forEach(node -> node.setDisable(true));

        Runnable updateChart = new Runnable() {
            @Override
            public void run() {
                if(sourceAddressRadioButton.isSelected()){
                    for(PcapLog pcapLog: pcapLogs){
                        if(pcapLog.getSourceAddress().equals("-")) continue;
                        int count = counter.getOrDefault(pcapLog.getSourceAddress(), 0);
                        counter.put(pcapLog.getSourceAddress(), count + 1);
                    }
                }
                else if(packetTypeRadioButton.isSelected()){
                    for(PcapLog pcapLog: pcapLogs){
                        int count = counter.getOrDefault(pcapLog.getProtocol(), 0);
                        counter.put(pcapLog.getProtocol(), count + 1);
                    }
                }
                else if(dateRadioButton.isSelected()){
                    for(PcapLog pcapLog: pcapLogs){
                        String time = pcapLog.getTimeval().split("-")[0]; // yyyy/MM/dd-HH:mm:ss
                        int count = counter.getOrDefault(time, 0);
                        counter.put(time, count + 1);
                    }
                }

                Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        pieChartControllerContainer.getChildren().forEach(node -> node.setDisable(false));
                        Set<Map.Entry<String, Integer>> entries = counter.entrySet();
                        Stream<Map.Entry<String, Integer>> sortedEntries = entries.stream().sorted(reverseOrder(Map.Entry.comparingByValue())).limit(chartThresholdSpinner.getValue());
                        sortedEntries.forEach(stringIntegerEntry -> pcapLogPieChart.getData().add(new PieChart.Data(stringIntegerEntry.getKey(), stringIntegerEntry.getValue())));
                    }
                });
            }
        };

        service.submit(updateChart);
    }

    Callback<TableColumn<PcapLog, String>, TableCell<PcapLog, String>> cellPayloadButtonFactory = new Callback<>() {
        @Override
        public TableCell<PcapLog, String> call(TableColumn<PcapLog, String> param) {
            return new TableCell<>() {
                final Button btn = new Button("Payload");

                @Override
                public void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty) {
                        setGraphic(null);
                    } else {
                        btn.setOnAction(event -> {
                            PcapLog payloadPcap = this.getTableRow().getItem();
                            String[] headerHexText = HexHelper.toString(payloadPcap.getHeader()).split(" ");
                            String[] bodyHexText = HexHelper.toString(payloadPcap.getBody()).split(" ");

                            StringBuilder editedHeaderHexText = new StringBuilder();
                            StringBuilder editedBodyHexText = new StringBuilder();

                            int counter = 0;
                            for(String text: headerHexText){
                                editedHeaderHexText.append(text).append(" ");
                                counter++;
                                if(counter == 8) {
                                    editedHeaderHexText.append(" ");
                                }
                                if(counter == 16){
                                    editedHeaderHexText.append("\n");
                                    counter = 0;
                                }
                            }

                            counter = 0;
                            for(String text: bodyHexText){
                                editedBodyHexText.append(text).append(" ");
                                counter++;
                                if(counter == 8) {
                                    editedBodyHexText.append(" ");
                                }
                                if(counter == 16){
                                    editedBodyHexText.append("\n");
                                    counter = 0;
                                }
                            }

                            headerTextArea.setText(editedHeaderHexText.toString());
                            bodyTextArea.setText(editedBodyHexText.toString());
                            if(payloadWindow.isShowing()) payloadWindow.close();
                            payloadWindow.show();
                        });
                        setGraphic(btn);
                    }
                    setText(null);
                }
            };
        }
    };

    Callback<TableColumn<PcapLog, String>, TableCell<PcapLog, String>> cellContextMenuFactory = new Callback<>() {
        @Override
        public TableCell<PcapLog, String> call(TableColumn<PcapLog, String> param) {
            TableCell<PcapLog, String> tableCell = new TableCell<>(){
                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (item != null){
                        setText(item);
                    }
                }
            };

            tableCell.setOnMouseClicked(event -> {
                if(event.getButton() == MouseButton.SECONDARY){
                    Map<FilterType, String> data = new HashMap<>();
                    PcapLog clickedPcapLog = tableCell.getTableRow().getItem();
                    if(tableCell.getTableColumn() == sourceAddressColumn){
                        data.put(FilterType.SOURCEADDRESS, clickedPcapLog.getSourceAddress());
                    }
                    else if(tableCell.getTableColumn() == destinationAddressColumn){
                        data.put(FilterType.DESTINATIONADDRESS, clickedPcapLog.getDestinationAddress());
                    }
                    else if(tableCell.getTableColumn() == protocolColumn){
                        data.put(FilterType.PROTOCOL, clickedPcapLog.getProtocol());
                    }
                    cellContextMenu.setUserData(data);
                    cellContextMenu.show(((Node)event.getSource()).getScene().getWindow(), event.getScreenX(), event.getScreenY());
                }
            });
            return tableCell;
        }
    };

    private final EventHandler<ActionEvent> onClickContextMenuFilter = new EventHandler<>() {
        @Override
        public void handle(ActionEvent event) {
            MenuItem origin = (MenuItem) event.getSource();
            @SuppressWarnings("unchecked") Map<FilterType, String> eventSourceColumn = (HashMap<FilterType, String>) origin.getParentPopup().getUserData();
            var entries = eventSourceColumn.entrySet();
            entries.forEach(filterTypeStringEntry -> {
                FilterType filterType = filterTypeStringEntry.getKey();
                ArrayList<String> filters = logFilters.get(filterType);
                String value = filterTypeStringEntry.getValue();

                if(filters.contains(value)){
                    new Alert(Alert.AlertType.ERROR, "This filter is already applied.").show();
                    return;
                }
                // filters.add(value); it duplicates filter because listener adds too.

                // add visual element(checkbox) in toolbar of tableview which shows what filtering option is set
                CheckBox newFilter = new CheckBox(String.format("%s: %s", filterType.toString(), value));
                newFilter.selectedProperty().addListener((observable, oldValue, newValue) -> {
                    if(newValue){
                        // if(!filters.contains(value)) filters.add(value);
                        filters.add(value);
                    } else {
                        filters.remove(value);
                    }
                });
                newFilter.setSelected(true);
                packetFilteringToolBar.getItems().add(newFilter);
            });
        }
    };

    // TODO: implement when filter is done.
    private final EventHandler<ActionEvent> onClickContextMenuBlock = new EventHandler<ActionEvent>() {
        @Override
        public void handle(ActionEvent event) {
            MenuItem origin = (MenuItem)event.getSource();
            //PcapLog pcapLog = origin.getTableRow().getItem();
            PcapLog pcapLog = (PcapLog)origin.getParentPopup().getUserData();
            System.out.println(pcapLog.getSourceAddress() + " is blocked.");
        }
    };
}
