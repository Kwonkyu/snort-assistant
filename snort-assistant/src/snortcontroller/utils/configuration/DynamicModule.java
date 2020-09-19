package snortcontroller.utils.configuration;

public class DynamicModule {
    String moduleType;
    String valueType;
    String value;

    public DynamicModule(String moduleType, String libraryType, String value) {
        this.moduleType = moduleType;
        this.valueType = libraryType;
        this.value = value;
    }

    public String getModuleType() {
        return moduleType;
    }

    public void setModuleType(String moduleType) {
        this.moduleType = moduleType;
    }

    public String getValueType() {
        return valueType;
    }

    public void setValueType(String valueType) {
        this.valueType = valueType;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public DynamicModule copy(){
        return new DynamicModule(moduleType, valueType, value);
    }
}

// check http://books.gigatux.nl/mirror/snortids/0596006616/snortids-CHP-5-SECT-2.html