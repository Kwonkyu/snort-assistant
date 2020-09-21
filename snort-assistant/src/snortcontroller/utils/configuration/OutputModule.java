package snortcontroller.utils.configuration;

public class OutputModule {
    String keyword;
    String option;
    String value;

    public OutputModule(String keyword, String option, String value) {
        this.keyword = keyword;
        this.option = option;
        this.value = value;
    }

    public String getKeyword() { return keyword; }

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

    public OutputModule copy(){
        return new OutputModule(keyword, option, value);
    }

    @Override
    public String toString() {
        return "OutputModule{" +
                "keyword='" + keyword + '\'' +
                ", option='" + option + '\'' +
                ", value='" + value + '\'' +
                '}';
    }
}
