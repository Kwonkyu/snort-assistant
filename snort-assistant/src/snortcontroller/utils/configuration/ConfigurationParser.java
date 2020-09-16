package snortcontroller.utils.configuration;

import java.io.File;
import java.util.ArrayList;

public class ConfigurationParser {
    File file;

    public ConfigurationParser(File file){
        this.file = file;
    }

    public ConfigurationParser(String location){
        file = new File(location);
    }

    public ArrayList<NetworkVariable> parseNetworkVariables(){
        NetworkVariableParser networkVariableParser = new NetworkVariableParser(file.getAbsolutePath());
        return networkVariableParser.parse();
    }

    // TODO: implement another parsings...
}
