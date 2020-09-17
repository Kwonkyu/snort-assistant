package snortcontroller.utils.configuration;

public class NetworkDecoder {
    String keyword;
    String name;
    String value;

    public NetworkDecoder(String keyword, String name, String value) {
        this.keyword = keyword;
        this.name = name;
        this.value = value;
    }

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
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
}
