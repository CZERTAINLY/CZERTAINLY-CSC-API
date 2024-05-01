package com.czertainly.signserver.csc.model;


import java.util.Map;

public class UserInfo {

    final Map<String, String> attributes;

    public UserInfo(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public String getAttribute(String key, String defaultValue) {
        return attributes.getOrDefault(key, defaultValue);
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }
}
