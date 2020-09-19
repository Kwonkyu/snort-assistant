package snortcontroller.utils.configuration;

public class Inclusion {
    private String keyword;
    private String value;

    public Inclusion(String keyword, String value) {
        this.keyword = keyword;
        this.value = value;
    }

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Inclusion copy(){
        return new Inclusion(keyword, value);
    }

    @Override
    public String toString() {
        return "Inclusion{" +
                "keyword='" + keyword + '\'' +
                ", value='" + value + '\'' +
                '}';
    }
}
