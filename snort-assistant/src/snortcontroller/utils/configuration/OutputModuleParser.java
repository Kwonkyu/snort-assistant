package snortcontroller.utils.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;

public class OutputModuleParser {
    File file;

    public OutputModuleParser(File file){
        this.file = file;
    }

    public OutputModuleParser(String location){
        file = new File(location);
    }

    public ArrayList<OutputModule> parse() throws FileNotFoundException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        ArrayList<OutputModule> parsedOutputModules = new ArrayList<>();
        br.lines().forEach(line -> {
            if(line.startsWith("output")){
                String[] strings = line.split(" ");
                parsedOutputModules.add(new OutputModule(strings[0], strings[1], line.substring(line.indexOf(strings[1])+strings[1].length())));
            }
        });
        return parsedOutputModules;
    }

}
