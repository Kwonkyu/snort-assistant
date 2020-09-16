package snortcontroller.utils.configuration;

import java.io.File;
import java.util.ArrayList;

public class NetworkVariableParser {
    File file;
    ArrayList<NetworkVariable> parsedVariables = new ArrayList<>();

    public NetworkVariableParser(File file){
        this.file = file;
    }

    public NetworkVariableParser(String location){
        file = new File(location);
    }

    public ArrayList<NetworkVariable> parse(){
        // TODO: implement parsing
        return parsedVariables;
    }
}
