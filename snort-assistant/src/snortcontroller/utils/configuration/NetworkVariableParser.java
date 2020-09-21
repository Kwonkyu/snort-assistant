package snortcontroller.utils.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;

public class NetworkVariableParser {
    File file;

    public NetworkVariableParser(File file){
        this.file = file;
    }

    public NetworkVariableParser(String location){
        file = new File(location);
    }

    public ArrayList<NetworkVariable> parse() throws FileNotFoundException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        ArrayList<NetworkVariable> networkVariables = new ArrayList<>();
        br.lines().forEach(line -> {
            if(line.startsWith("var") || line.startsWith("ipvar") || line.startsWith("portvar")){
                String[] strings = line.split(" ");
                networkVariables.add(new NetworkVariable(strings[0], strings[1], strings[2]));
            }
        });
        return networkVariables;
    }
}
