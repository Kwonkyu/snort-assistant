package snortcontroller.main;

import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.chart.PieChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Callback;
import snortcontroller.utils.pcap.PcapLog;
import snortcontroller.utils.pcap.PcapParser;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.ResourceBundle;

public class PcapParserController implements Initializable {
    // Toolbar components.
	@FXML
    TextField pcapFilePathTextField;
	@FXML
    Button findButton;
	@FXML
    Button openButton;

	// Main components.
	@FXML
    TableView<PcapLog> pcapLogTableView;
    @FXML
    PieChart pcapLogPieChart;

    // Side components.
    @FXML
    RadioButton sourceAddressRadioButton;
    @FXML
    RadioButton packetTypeRadioButton;
    @FXML
    RadioButton dateRadioButton;

    File pcapFile;
    final FileChooser fileChooser = new FileChooser();
    FileChooser.ExtensionFilter pcapFilter = new FileChooser.ExtensionFilter("libpcap formatted log", "*.pcap");

    PcapParser pcapParser;
    ArrayList<PcapLog> pcapLogs;

    TableColumn<PcapLog, String> sourceAddressColumn;
    TableColumn<PcapLog, String> sourceHwAddressColumn;
    TableColumn<PcapLog, String> sourcePortColumn;
    TableColumn<PcapLog, String> destinationAddressColumn;
    TableColumn<PcapLog, String> destinationHwAddressColumn;
    TableColumn<PcapLog, String> destinationPortColumn;
    TableColumn<PcapLog, String> timevalColumn;
    TableColumn<PcapLog, String> payloadColumn;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // 'Find' button to open file chooser window.
        fileChooser.getExtensionFilters().add(pcapFilter);
        findButton.setOnAction(event -> {
            if (pcapFile != null){ // already opened log file
                fileChooser.setInitialDirectory(new File(pcapFile.getParent()));
            }
            File selectedFile = fileChooser.showOpenDialog(((Node)event.getSource()).getScene().getWindow());
            if (selectedFile != null){
                pcapFile = selectedFile;
                pcapFilePathTextField.setText(pcapFile.getAbsolutePath());
            }
        });

        // 'Open' button to open choosed file.
        openButton.setOnAction(event -> {
            pcapParser = new PcapParser(pcapFilePathTextField.getText());
            try {
                pcapParser.parse();
                pcapLogs = pcapParser.getParsedPackets();
            } catch (Exception e) {
                System.err.println(e.getLocalizedMessage());
            }

            // TODO: activate table
            pcapLogTableView.setItems(FXCollections.observableArrayList(pcapLogs));

            // TODO: activate chart
        });

        // TODO: initialize table with table columns
        pcapLogTableView.setEditable(true);
        sourceAddressColumn = new TableColumn<>("Source Address");
        sourceHwAddressColumn = new TableColumn<>("Source MAC Address");
        sourcePortColumn = new TableColumn<>("Source Port");
        destinationAddressColumn = new TableColumn<>("Destination Address");
        destinationHwAddressColumn = new TableColumn<>("Destination MAC Address");
        destinationPortColumn = new TableColumn<>("Destination Port");
        timevalColumn = new TableColumn<>("Time");
        payloadColumn = new TableColumn<>("Payload");

        // column layout settings.
        sourceAddressColumn.setMinWidth(150.0);
        sourceHwAddressColumn.setMinWidth(200.0);
        sourcePortColumn.setMinWidth(100.0);
        destinationAddressColumn.setMinWidth(175.0);
        destinationHwAddressColumn.setMinWidth(200.0);
        destinationPortColumn.setMinWidth(150.0);
        timevalColumn.setMinWidth(250.0);
        payloadColumn.setMinWidth(100.0);

        // read values from pcap log.
        sourceAddressColumn.setCellValueFactory(new PropertyValueFactory<PcapLog, String>("sourceAddress"));
        sourceHwAddressColumn.setCellValueFactory(new PropertyValueFactory<PcapLog, String>("sourceHwAddress"));
        sourcePortColumn.setCellValueFactory(new PropertyValueFactory<PcapLog, String>("sourcePort"));
        destinationAddressColumn.setCellValueFactory(new PropertyValueFactory<PcapLog, String>("destinationAddress"));
        destinationHwAddressColumn.setCellValueFactory(new PropertyValueFactory<PcapLog, String>("destinationHwAddress"));
        destinationPortColumn.setCellValueFactory(new PropertyValueFactory<PcapLog, String>("destinationPort"));
        timevalColumn.setCellValueFactory(new PropertyValueFactory<PcapLog, String>("timeval"));

        Callback<TableColumn<PcapLog, String>, TableCell<PcapLog, String>> buttonCellFactory =
                new Callback<TableColumn<PcapLog, String>, TableCell<PcapLog, String>>() {
                    @Override
                    public TableCell<PcapLog, String> call(final TableColumn<PcapLog, String> param) {
                        final TableCell<PcapLog, String> cell = new TableCell<PcapLog, String>() {
                            final Button btn = new Button("Payload");

                            @Override
                            public void updateItem(String item, boolean empty) {
                                super.updateItem(item, empty);
                                if (empty) {
                                    setGraphic(null);
                                    setText(null);
                                } else {
                                    btn.setOnAction(event -> {
                                        System.out.println("TEST PAYLOAD");
                                    });
                                    setGraphic(btn);
                                    setText(null);
                                }
                            }
                        };
                        return cell;
                    }
                };
        payloadColumn.setCellFactory(buttonCellFactory);


        pcapLogTableView.getColumns().addAll(timevalColumn, sourceAddressColumn, sourceHwAddressColumn, sourcePortColumn,
                destinationAddressColumn, destinationHwAddressColumn, destinationPortColumn, payloadColumn);

        // TODO: radio button handler
    }
}
