package org.yueweb3j.protocol.core.methods.response;

import org.yueweb3j.protocol.core.Response;

import java.util.List;
import java.util.Map;


public class YueBasePermission extends Response<Map<String,Boolean>> {
    public boolean getSendTransactionPermission() {
        return getResult().get("sendtransaction");
    }

    public boolean getCreateContractPermission() {
        return getResult().get("createContract");
    }
}
