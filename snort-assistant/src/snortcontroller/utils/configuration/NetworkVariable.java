package snortcontroller.utils.configuration;

import javafx.beans.property.StringProperty;

public class NetworkVariable {
    String type;
    String name;
    String value;

    public NetworkVariable(String type, String name, String value){
        this.type = type;
        this.name = name;
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public NetworkVariable copy(){
        return new NetworkVariable(type, name, value);
    }

    @Override
    public String toString() {
        return "NetworkVariable{" +
                "type='" + type + '\'' +
                ", name='" + name + '\'' +
                ", value='" + value + '\'' +
                '}';
    }
}
