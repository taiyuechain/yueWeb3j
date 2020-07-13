package org.yueweb3j.protocol.core.methods.response;

import org.yueweb3j.protocol.core.Response;

import java.util.List;


public class YueBasePermission extends Response<List<Boolean>> {
    public boolean getSendTransactionPermission() {
        return getResult().get(0);
    }

    public boolean getCreateContractPermission() {
        return getResult().get(1);
    }
}
