package snortcontroller.utils.rules;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class RuleParser {
    Pattern patternRuleHeader = Pattern.compile("^[^(]+");
    Pattern patternRuleBody = Pattern.compile("[(].+[)]");
    Pattern patternRuleBodyElements = Pattern.compile("[^ (].+?;");
    Matcher matcher = null;

    String fileLocation;
    BufferedReader fileReader = null;
    ArrayList<Rule> parsedRules = new ArrayList<>();

    public RuleParser(){

    }

    public RuleParser(String location) {
        fileLocation = location;
    }

    public ArrayList<Rule> getParsedRules() {
        return parsedRules;
    }

    public void parse() throws FileNotFoundException {
        fileReader = new BufferedReader(new FileReader(fileLocation));

        Stream<String> rules = fileReader.lines();
        // rules.forEach(System.out::println);
        rules.forEach(new Consumer<String>() {
            @Override
            public void accept(String rule) {
                if(rule.startsWith("#") || rule.length() == 0) return;
                // parseHead(s);
                // parseBody(s);
                Rule ruleInstance;
                matcher = patternRuleHeader.matcher(rule);
                if(matcher.find()){
                    String ruleHeader = matcher.group();
                    String[] ruleHeaderElements = ruleHeader.split(" ");
                    try {
                        String ruleAction = ruleHeaderElements[0];
                        String ruleProtocol = ruleHeaderElements[1];
                        String ruleSourceAddress = ruleHeaderElements[2];
                        String ruleSourcePort = ruleHeaderElements[3];
                        String ruleDirection = ruleHeaderElements[4];
                        String ruleDestinationAddress = ruleHeaderElements[5];
                        String ruleDestinationPort = ruleHeaderElements[6];
                        ruleInstance = new Rule(ruleAction, ruleProtocol, ruleSourceAddress, ruleSourcePort,
                                ruleDirection, ruleDestinationAddress, ruleDestinationPort, null);
                    } catch (ArrayIndexOutOfBoundsException e){
                        System.err.println("Wrong format!(Insufficient header elements)");
                        return;
                    }
                } else {
                    System.err.println("Wrong format!(No header found)");
                    return;
                }

                Map<String, String> ruleBodyElements = new LinkedHashMap<>();
                matcher = patternRuleBody.matcher(rule);
                if(matcher.find()){
                    // if(matcher.groupCount() > 0){ don't use groupCount before find, I guess.
                    String ruleBody = matcher.group();
                    matcher = patternRuleBodyElements.matcher(ruleBody);
                    try {
                        while (matcher.find()) {
                            String[] ruleBodyElement = matcher.group().split(":");
                            if(ruleBodyElement.length > 1){
                                ruleBodyElements.put(ruleBodyElement[0], ruleBodyElement[1].substring(0, ruleBodyElement[1].length()-1));
                            } else {
                                ruleBodyElements.put(ruleBodyElement[0].substring(0, ruleBodyElement[0].length()-1), "");
                            }
                        }
                    } catch (ArrayIndexOutOfBoundsException e){
                        System.err.println("Wrong format!(Insufficient body element pair)");
                    }
                    /*try {
                        while (matcher.find()) {
                            String[] ruleBodyElement = matcher.group().split(":");
                            ruleBodyElements.put(ruleBodyElement[0], ruleBodyElement[1].substring(0, ruleBodyElement[1].length()-1));
                        }
                    } catch (ArrayIndexOutOfBoundsException e){
                        System.err.println("Wrong format!(Insufficient body element pair)");
                    }*/
                }
                ruleInstance.setRuleBodyElements(ruleBodyElements);
                parsedRules.add(ruleInstance);
            }
        });
    }
}
