package snortcontroller.utils.configuration;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;

public class ConfigurationParser {
    File file;

    public ConfigurationParser(File file){
        this.file = file;
    }

    public ConfigurationParser(String location){
        file = new File(location);
    }

    public void parse(){
        // TODO: integrate these?
    }

    public ArrayList<NetworkVariable> parseNetworkVariables() throws FileNotFoundException {
        NetworkVariableParser networkVariableParser = new NetworkVariableParser(file.getAbsolutePath());
        return networkVariableParser.parse();
    }

    public ArrayList<NetworkDecoder> parseNetworkDecoders() throws FileNotFoundException {
        NetworkDecoderParser networkDecoderParser = new NetworkDecoderParser(file.getAbsolutePath());
        return networkDecoderParser.parse();
    }

    public ArrayList<DynamicModule> parseDynamicModules() throws FileNotFoundException {
        DynamicModuleParser dynamicModuleParser = new DynamicModuleParser(file.getAbsoluteFile());
        return dynamicModuleParser.parse();
    }
    // TODO: implement another parsings...
}
