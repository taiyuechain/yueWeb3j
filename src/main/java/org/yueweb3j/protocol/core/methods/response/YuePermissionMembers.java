package org.yueweb3j.protocol.core.methods.response;

import org.yueweb3j.protocol.core.Response;

import java.util.List;
import java.util.Map;


public class YuePermissionMembers extends Response<Map<String, List<String>>> {
    public List<String> getWhiteMembers() {
        return getResult().get("WhiteMembers");
    }

    public List<String> getWhiteManager() {
        return getResult().get("WhiteManager");
    }

    public List<String> getBlackMembers() {
        return getResult().get("BlackMembers");
    }

    public List<String> getBlackManager() {
        return getResult().get("BlackManager");
    }
}
