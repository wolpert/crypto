package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.Utilities;

import java.util.Map;

/**
 * BSD-Style License 2016
 */
public class SensitiveDetails {

    private String id;
    private transient String username;
    private transient String password;
    private transient String notes;
    private transient Map<String, String> attr;

    public SensitiveDetails() {
        this.id = Utilities.getUuid();
    }

    public SensitiveDetails(String username, String password, String notes, String id, Map<String, String> attr) {
        this.username = username;
        this.password = password;
        this.notes = notes;
        this.id = id;
        this.attr = attr;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Map<String, String> getAttr() {
        return attr;
    }

    public void setAttr(Map<String, String> attr) {
        this.attr = attr;
    }
}
