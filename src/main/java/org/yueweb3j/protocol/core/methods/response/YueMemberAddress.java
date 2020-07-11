package org.yueweb3j.protocol.core.methods.response;

import org.yueweb3j.protocol.core.Response;

import java.util.List;


public class YueMemberAddress extends Response<List<String>> {
    public List<String> getMember(){
        return getResult();
    }
}
