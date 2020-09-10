package snortcontroller.utils.rules;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Rule {
    String ruleAction; // alert, log, pass, drop, reject, sdrop
    String ruleProtocol;
    String ruleSourceAddress;
    String ruleSourcePort;
    String ruleDirection; // '->' and '<>'. '<-' doesn't exist.
    String ruleDestinationAddress;
    String ruleDestinationPort;
    Map<String, String> ruleBodyElements;

    public Rule(String ruleAction, String ruleProtocol, String ruleSourceAddress, String ruleSourcePort, String ruleDirection,
                String ruleDestinationAddress, String ruleDestinationPort, Map<String, String> ruleBodyElements){
        this.ruleAction = ruleAction;
        this.ruleProtocol = ruleProtocol;
        this.ruleSourceAddress = ruleSourceAddress;
        this.ruleSourcePort = ruleSourcePort;
        this.ruleDirection = ruleDirection;
        this.ruleDestinationAddress = ruleDestinationAddress;
        this.ruleDestinationPort = ruleDestinationPort;
        this.ruleBodyElements = ruleBodyElements;
    }

    public String getRuleAction() {
        return ruleAction;
    }

    public void setRuleAction(String ruleAction) {
        this.ruleAction = ruleAction;
    }

    public String getRuleProtocol() {
        return ruleProtocol;
    }

    public void setRuleProtocol(String ruleProtocol) {
        this.ruleProtocol = ruleProtocol;
    }

    public String getRuleSourceAddress() {
        return ruleSourceAddress;
    }

    public void setRuleSourceAddress(String ruleSourceAddress) {
        this.ruleSourceAddress = ruleSourceAddress;
    }

    public String getRuleSourcePort() {
        return ruleSourcePort;
    }

    public void setRuleSourcePort(String ruleSourcePort) {
        this.ruleSourcePort = ruleSourcePort;
    }

    public String getRuleDirection() {
        return ruleDirection;
    }

    public void setRuleDirection(String ruleDirection) {
        this.ruleDirection = ruleDirection;
    }

    public String getRuleDestinationAddress() {
        return ruleDestinationAddress;
    }

    public void setRuleDestinationAddress(String ruleDestinationAddress) {
        this.ruleDestinationAddress = ruleDestinationAddress;
    }

    public String getRuleDestinationPort() {
        return ruleDestinationPort;
    }

    public void setRuleDestinationPort(String ruleDestinationPort) {
        this.ruleDestinationPort = ruleDestinationPort;
    }

    public Map<String, String> getRuleBodyElements() {
        return ruleBodyElements;
    }

    public void setRuleBodyElements(Map<String, String> ruleBody) {
        this.ruleBodyElements = ruleBody;
    }

    @Override
    public String toString() {
        // return super.toString();
        StringBuilder ruleBodyString = new StringBuilder();
        Set<Map.Entry<String, String>> entries = ruleBodyElements.entrySet();
        for(Map.Entry<String, String> entry: entries){
            ruleBodyString.append(String.format(" %s:%s", entry.getKey(), entry.getValue()));
        }
        return String.format("[ Rule %s ] %s %s packet with src/%s:%s %s dst/%s:%s - %s",
                this.hashCode(), ruleAction, ruleProtocol, ruleSourceAddress, ruleSourcePort, ruleDirection, ruleDestinationAddress,
                ruleDestinationPort, ruleBodyString.toString());
    }

    public Rule copy() {
        Rule retVal = new Rule(ruleAction, ruleProtocol, ruleSourceAddress, ruleSourcePort, ruleDirection, ruleDestinationAddress,
                ruleDestinationPort, null);
        Map<String, String> retValBodyElements = new HashMap<>();
        ruleBodyElements.forEach(retValBodyElements::put);
        retVal.setRuleBodyElements(retValBodyElements);
        return retVal;
    }
}
