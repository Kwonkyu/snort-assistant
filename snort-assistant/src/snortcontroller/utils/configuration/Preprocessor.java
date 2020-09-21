package snortcontroller.utils.configuration;

public class Preprocessor {
    String keyword;
    String option;
    String value;

    public Preprocessor(String keyword, String option, String value) {
        this.keyword = keyword;
        this.option = option;
        this.value = value;
    }

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public String getOption() {
        return option;
    }

    public void setOption(String option) {
        this.option = option;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Preprocessor copy(){
        return new Preprocessor(keyword, option, value);
    }

    @Override
    public String toString() {
        return "Preprocessor{" +
                "keyword='" + keyword + '\'' +
                ", option='" + option + '\'' +
                ", value='" + value + '\'' +
                '}';
    }
}
