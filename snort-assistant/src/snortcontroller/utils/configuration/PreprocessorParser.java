package snortcontroller.utils.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;

public class PreprocessorParser {
    File file;

    public PreprocessorParser(File file){
        this.file = file;
    }

    public PreprocessorParser(String location){
        file = new File(location);
    }

    public ArrayList<Preprocessor> parse() throws FileNotFoundException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        ArrayList<String> lines = new ArrayList<>();
        ArrayList<Preprocessor> parsedPreprocessors = new ArrayList<>();
        boolean endsWithBackslash = false;
        String keyword = "", option = "";
        StringBuilder valueStrings = new StringBuilder();

        br.lines().forEach(lines::add);
        for(String line: lines){
            if(line.startsWith("preprocessor") && !endsWithBackslash){
                String[] strings = line.split(" ");
                if(strings.length < 3){ // ex: preprocessor normalize_ip4
                    parsedPreprocessors.add(new Preprocessor(strings[0], strings[1], ""));
                } else { // ex: preprocessor stream5_udp: timeout 180 [\ ...]
                    if(line.endsWith("\\")) {
                        endsWithBackslash = true;
                        keyword = strings[0];
                        option = strings[1];
                        // TODO: if option name and strings element has same word, problem happens. need baseline to start search.
                        valueStrings.append(line.substring(line.indexOf(strings[2], line.indexOf(strings[1])+strings[1].length())));
                    } else {
                        parsedPreprocessors.add(new Preprocessor(strings[0], strings[1], line.substring(line.indexOf(strings[2], line.indexOf(strings[1])+strings[1].length()))));
                    }
                }
            } else if(endsWithBackslash) {
                String strippedLine = line.strip();
                valueStrings.append(strippedLine);
                if(!strippedLine.endsWith("\\")) {
                    endsWithBackslash = false;
                    parsedPreprocessors.add(new Preprocessor(keyword, option, valueStrings.toString()));
                    valueStrings = new StringBuilder();
                }
            }
        }
        return parsedPreprocessors;
    }
}
