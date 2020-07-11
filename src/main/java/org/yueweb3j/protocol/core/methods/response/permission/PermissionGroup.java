package org.yueweb3j.protocol.core.methods.response.permission;

import org.yueweb3j.protocol.core.methods.response.YueMemberAddress;

public class PermissionGroup {
    private String groupKey;
    private String creator;
    private String id;
    private String name;
    private YueMemberAddress whiteMembers;
    private YueMemberAddress whiteManager;
    private YueMemberAddress blackMembers;
    private YueMemberAddress blackManager;

    public PermissionGroup(String groupKey, String creator, String id, String name, YueMemberAddress whiteMembers,
                           YueMemberAddress whiteManager, YueMemberAddress blackMembers, YueMemberAddress blackManager) {
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

    public YueMemberAddress getWhiteMembers() {
        return whiteMembers;
    }

    public void setWhiteMembers(YueMemberAddress whiteMembers) {
        this.whiteMembers = whiteMembers;
    }

    public YueMemberAddress getWhiteManager() {
        return whiteManager;
    }

    public void setWhiteManager(YueMemberAddress whiteManager) {
        this.whiteManager = whiteManager;
    }

    public YueMemberAddress getBlackMembers() {
        return blackMembers;
    }

    public void setBlackMembers(YueMemberAddress blackMembers) {
        this.blackMembers = blackMembers;
    }

    public YueMemberAddress getBlackManager() {
        return blackManager;
    }

    public void setBlackManager(YueMemberAddress blackManager) {
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
