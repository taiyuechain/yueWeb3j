package org.yueweb3j.protocol.core.methods.response.permission;

import org.yueweb3j.protocol.core.methods.response.YueMemberAddress;

import java.security.Permission;
import java.util.List;

public class PermissionGroup {
    private String groupKey;
    private String creator;
    private String id;
    private String name;
    private List<String> whiteMembers;
    private List<String> whiteManager;
    private List<String> blackMembers;
    private List<String> blackManager;
    public PermissionGroup(){

    }
    public PermissionGroup(String groupKey, String creator, String id, String name, List<String> whiteMembers,
                           List<String> whiteManager, List<String> blackMembers, List<String> blackManager) {
        this.groupKey = groupKey;
        this.creator = creator;
        this.id = id;
        this.name = name;
        this.whiteMembers = whiteMembers;
        this.whiteManager = whiteManager;
        this.blackMembers = blackMembers;
        this.blackManager = blackManager;
    }

    public String getGroupKey() {
        return groupKey;
    }

    public void setGroupKey(String groupKey) {
        this.groupKey = groupKey;
    }

    public String getCreator() {
        return creator;
    }

    public void setCreator(String creator) {
        this.creator = creator;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getWhiteMembers() {
        return whiteMembers;
    }

    public void setWhiteMembers(List<String> whiteMembers) {
        this.whiteMembers = whiteMembers;
    }

    public List<String> getWhiteManager() {
        return whiteManager;
    }

    public void setWhiteManager(List<String> whiteManager) {
        this.whiteManager = whiteManager;
    }

    public List<String> getBlackMembers() {
        return blackMembers;
    }

    public void setBlackMembers(List<String> blackMembers) {
        this.blackMembers = blackMembers;
    }

    public List<String> getBlackManager() {
        return blackManager;
    }

    public void setBlackManager(List<String> blackManager) {
        this.blackManager = blackManager;
    }

    @Override
    public String toString() {
        return "PermissionGroup{" +
                "groupKey='" + groupKey + '\'' +
                ", creator='" + creator + '\'' +
                ", id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", whiteMembers=" + whiteMembers +
                ", whiteManager=" + whiteManager +
                ", blackMembers=" + blackMembers +
                ", blackManager=" + blackManager +
                '}';
    }
}
