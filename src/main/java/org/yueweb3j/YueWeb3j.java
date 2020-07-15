package org.yueweb3j;

import org.yueweb3j.crypto.Sign;
import org.yueweb3j.protocol.Web3j;
import org.yueweb3j.protocol.http.HttpService;


public class YueWeb3j {
    /**
     *
     * 初始化加密 默认国密 可以不初始化
     * @param encryptionMode  0 : "secp256k1"  1: "sm2p256v1"
     */
    public static void init(int encryptionMode){
        Sign.init(encryptionMode);
    }

    /**
     * 初始化加密 并返回Web3j
     * @param host 节点Ip
     * @param encryptionMode 0 : "secp256k1"  1: "sm2p256v1"
     * @return web3j
     */
    public static Web3j init(String host,int encryptionMode){
        Sign.init(encryptionMode);
        return Web3j.build(new HttpService(host));
    }


    /**
     * 初始化Web3j
     * @param host 节点Ip
     * @return web3j
     */
    public static Web3j init(String host){
        return Web3j.build(new HttpService(host));
    }

}
