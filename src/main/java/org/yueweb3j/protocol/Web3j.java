/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.yueweb3j.protocol;

import org.yueweb3j.config.Constant;
import org.yueweb3j.crypto.Sign;
import org.yueweb3j.protocol.core.Batcher;
import org.yueweb3j.protocol.core.YueInterface;
import org.yueweb3j.protocol.core.JsonRpc2_0Web3j;
import org.yueweb3j.protocol.rx.Web3jRx;

import java.util.concurrent.ScheduledExecutorService;

/**
 * JSON-RPC Request object building factory.
 */
public interface Web3j extends YueInterface, Web3jRx, Batcher {
    /**
     * Construct a new Web3j instance.
     *
     * @param web3jService web3j service instance - i.e. HTTP or IPC
     * @param encryptionMode 0 : "secp256k1"  1: "sm2p256v1"
     * @return new Web3j instance
     *
     */
    static Web3j build(Web3jService web3jService, int encryptionMode) {
        Constant.EncryptionMode = encryptionMode;
        Sign.init();
        return new JsonRpc2_0Web3j(web3jService);
    }

    /**
     * Construct a new Web3j instance; for sm2p256v1;
     * @param web3jService web3jService web3j service instance - i.e. HTTP or IPC
     * @return new  sm2p256v1 Web3j instance
     */
    static Web3j build(Web3jService web3jService) {
        return build(web3jService,1);
    }


    /**
     * Construct a new Web3j instance.
     *
     * @param web3jService             web3j service instance - i.e. HTTP or IPC
     * @param pollingInterval          polling interval for responses from network nodes
     * @param scheduledExecutorService executor service to use for scheduled tasks. <strong>You are
     *                                 responsible for terminating this thread pool</strong>
     * @return new Web3j instance
     */
    static Web3j build(
            Web3jService web3jService,
            long pollingInterval,
            ScheduledExecutorService scheduledExecutorService) {
        return new JsonRpc2_0Web3j(web3jService, pollingInterval, scheduledExecutorService);
    }

    /**
     * Shutdowns a Web3j instance and closes opened resources.
     */
    void shutdown();
}
