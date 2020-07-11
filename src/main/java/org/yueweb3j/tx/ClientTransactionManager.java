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
package org.yueweb3j.tx;

import java.io.IOException;
import java.math.BigInteger;

import org.yueweb3j.protocol.Web3j;
import org.yueweb3j.protocol.core.DefaultBlockParameter;
import org.yueweb3j.protocol.core.methods.request.Transaction;
import org.yueweb3j.protocol.core.methods.response.YueCall;
import org.yueweb3j.protocol.core.methods.response.YueGetCode;
import org.yueweb3j.protocol.core.methods.response.YueSendTransaction;
import org.yueweb3j.tx.response.TransactionReceiptProcessor;

/**
 * TransactionManager implementation for using an YueInterface node to transact.
 *
 * <p><b>Note</b>: accounts must be unlocked on the node for transactions to be successful.
 */
public class ClientTransactionManager extends TransactionManager {

    private final Web3j web3j;

    public ClientTransactionManager(Web3j web3j, String fromAddress) {
        super(web3j, fromAddress);
        this.web3j = web3j;
    }

    public ClientTransactionManager(
            Web3j web3j, String fromAddress, int attempts, int sleepDuration) {
        super(web3j, attempts, sleepDuration, fromAddress);
        this.web3j = web3j;
    }

    public ClientTransactionManager(
            Web3j web3j,
            String fromAddress,
            TransactionReceiptProcessor transactionReceiptProcessor) {
        super(transactionReceiptProcessor, fromAddress);
        this.web3j = web3j;
    }

    @Override
    public YueSendTransaction sendTransaction(
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            String data,
            BigInteger value,
            boolean constructor)
            throws IOException {

        Transaction transaction =
                new Transaction(getFromAddress(), null, gasPrice, gasLimit, to, value, data);

        return web3j.yueSendTransaction(transaction).send();
    }

    @Override
    public YueSendTransaction sendTransactionEIP1559(
            BigInteger gasPremium,
            BigInteger feeCap,
            BigInteger gasLimit,
            String to,
            String data,
            BigInteger value,
            boolean constructor)
            throws IOException {

        Transaction transaction =
                new Transaction(
                        getFromAddress(),
                        null,
                        null,
                        gasLimit,
                        to,
                        value,
                        data,
                        gasPremium,
                        feeCap);

        return web3j.yueSendTransaction(transaction).send();
    }

    @Override
    public String sendCall(String to, String data, DefaultBlockParameter defaultBlockParameter)
            throws IOException {
        YueCall yueCall =
                web3j.yueCall(
                                Transaction.createEthCallTransaction(getFromAddress(), to, data),
                                defaultBlockParameter)
                        .send();

        assertCallNotReverted(yueCall);
        return yueCall.getValue();
    }

    @Override
    public YueGetCode getCode(
            final String contractAddress, final DefaultBlockParameter defaultBlockParameter)
            throws IOException {
        return web3j.yueGetCode(contractAddress, defaultBlockParameter).send();
    }
}
