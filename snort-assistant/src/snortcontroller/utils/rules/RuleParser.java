package snortcontroller.utils.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RuleParser {
    String testLog = "alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"ATTACK-RESPONSES directory listing\"; " +
            "flow:established; content:\"Volume Serial Number\"; classtype:bad-unknown; sid:1292; rev:9;)";

    Pattern patternBody = Pattern.compile("\\w+:.+?;");
    Matcher matcher = null;

    public RuleParser(){

    }

    public void parseBody(){
        matcher = patternBody.matcher(testLog);
        while(matcher.find()){
            System.out.println("Result: " + matcher.group());
        }
    }
}
