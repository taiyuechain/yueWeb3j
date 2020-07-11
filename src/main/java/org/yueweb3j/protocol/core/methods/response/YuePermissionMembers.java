package org.yueweb3j.protocol.core.methods.response;

import org.yueweb3j.protocol.core.Response;

import java.util.List;


public class YuePermissionMembers extends Response<List<YueMemberAddress>> {
    public List<String> getWhileMembers() {
        return getResult().get(0).getMember();
    }

    public List<String> getWhileWhiteManager() {
        return getResult().get(1).getMember();
    }

    public List<String> getBlackMembers() {
        return getResult().get(2).getMember();
    }

    public List<String> getBlackManager() {
        return getResult().get(3).getMember();
    }
}
