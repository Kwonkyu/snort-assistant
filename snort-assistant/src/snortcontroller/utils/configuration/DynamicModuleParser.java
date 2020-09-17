package snortcontroller.utils.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;

public class DynamicModuleParser {
    File file;

    public DynamicModuleParser(File file){
        this.file = file;
    }

    public DynamicModuleParser(String location){
        file = new File(location);
    }

    public ArrayList<DynamicModule> parse() throws FileNotFoundException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        ArrayList<DynamicModule> dynamicModules = new ArrayList<>();
        br.lines().forEach(line -> {
            if(line.startsWith("dynamicpreprocessor") || line.startsWith("dynamicengine") || line.startsWith("dynamicdetection")){
                String[] strings = line.split(" ");
                if(strings.length < 3){ // implicit valueType.
                    if(strings[1].charAt(strings[1].length()-1) == '/'){
                        dynamicModules.add(new DynamicModule(strings[0], "directory", strings[1]));
                    } else {
                        dynamicModules.add(new DynamicModule(strings[0], "file", strings[1]));
                    }
                } else { // explicit valueType.
                    dynamicModules.add(new DynamicModule(strings[0], strings[1], strings[2]));
                }
            }
        });
        return dynamicModules;
    }
}
