package snortcontroller.utils.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;

public class InclusionParser {
    File file;

    public InclusionParser(File file){ this.file = file; }

    public InclusionParser(String location){ file = new File(location); }

    public ArrayList<Inclusion> parse() throws FileNotFoundException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        ArrayList<Inclusion> parsedInclusions = new ArrayList<>();
        br.lines().forEach(line -> {
            if(line.startsWith("include")){
                String[] strings = line.split(" ");
                parsedInclusions.add(new Inclusion(strings[0], line.substring(strings[0].length() + 1)));
            }
        });
        return parsedInclusions;
    }
}
