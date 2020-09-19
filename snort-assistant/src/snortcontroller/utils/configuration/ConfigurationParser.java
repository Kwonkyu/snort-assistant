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

    // TODO: integrate these?
    public ArrayList<NetworkVariable> parseNetworkVariables() throws FileNotFoundException {
        NetworkVariableParser networkVariableParser = new NetworkVariableParser(file);
        return networkVariableParser.parse();
    }

    public ArrayList<NetworkDecoder> parseNetworkDecoders() throws FileNotFoundException {
        NetworkDecoderParser networkDecoderParser = new NetworkDecoderParser(file);
        return networkDecoderParser.parse();
    }

    public ArrayList<DynamicModule> parseDynamicModules() throws FileNotFoundException {
        DynamicModuleParser dynamicModuleParser = new DynamicModuleParser(file);
        return dynamicModuleParser.parse();
    }

    public ArrayList<Preprocessor> parsePreprocessors() throws FileNotFoundException {
        PreprocessorParser preprocessorParser = new PreprocessorParser(file);
        return preprocessorParser.parse();
    }

    public ArrayList<OutputModule> parseOutputModules() throws FileNotFoundException {
        OutputModuleParser outputModuleParser = new OutputModuleParser(file);
        return outputModuleParser.parse();
    }

    public ArrayList<Inclusion> parseInclusions() throws FileNotFoundException {
        InclusionParser inclusionParser = new InclusionParser(file);
        return inclusionParser.parse();
    }
}
