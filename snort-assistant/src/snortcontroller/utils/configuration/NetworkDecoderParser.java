package snortcontroller.utils.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;

public class NetworkDecoderParser {
    File file;

    public NetworkDecoderParser(String location){
        file = new File(location);
    }

    public NetworkDecoderParser(File file){
        this.file = file;
    }

    public ArrayList<NetworkDecoder> parse() throws FileNotFoundException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        ArrayList<NetworkDecoder> networkDecoders = new ArrayList<>();
        br.lines().forEach(line -> {
            if(line.startsWith("config")){
                String[] strings = line.split(" ");
                if(strings.length < 3){ // ex: config daemon
                    networkDecoders.add(new NetworkDecoder(strings[0], strings[1], ""));
                } else { // ex: config interface: <interface name>
                    if(strings[1].endsWith(":")){ // double check
                        String value = line.substring(line.indexOf(strings[2]), line.length());
                        networkDecoders.add(new NetworkDecoder(strings[0], strings[1], value));
                    }
                }
            }
        });
        return networkDecoders;
    }
}
