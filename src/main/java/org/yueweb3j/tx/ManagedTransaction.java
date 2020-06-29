/*
 * Copyright 2019 Web3 Labs LTD.
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

import org.yueweb3j.ens.EnsResolver;
import org.yueweb3j.protocol.Web3j;
import org.yueweb3j.protocol.core.DefaultBlockParameter;
import org.yueweb3j.protocol.core.methods.response.YueGasPrice;
import org.yueweb3j.protocol.core.methods.response.TransactionReceipt;
import org.yueweb3j.protocol.exceptions.TransactionException;

/** Generic transaction manager. */
public abstract class ManagedTransaction {

    /**
     * @deprecated use ContractGasProvider
     * @see org.yueweb3j.tx.gas.DefaultGasProvider
     */
    public static final BigInteger GAS_PRICE = BigInteger.valueOf(22_000_000_000L);

    protected Web3j web3j;

    protected TransactionManager transactionManager;

    protected EnsResolver ensResolver;

    protected ManagedTransaction(Web3j web3j, TransactionManager transactionManager) {
        this(new EnsResolver(web3j), web3j, transactionManager);
    }

    protected ManagedTransaction(
            EnsResolver ensResolver, Web3j web3j, TransactionManager transactionManager) {
        this.transactionManager = transactionManager;
        this.ensResolver = ensResolver;
        this.web3j = web3j;
    }

    /**
     * This should only be used in case you need to get the {@link EnsResolver#getSyncThreshold()}
     * parameter, which dictates the threshold in milliseconds since the last processed block
     * timestamp should be to considered in sync the blockchain.
     *
     * <p>It is currently experimental and only used in ENS name resolution, but will probably be
     * made available for read calls in the future.
     *
     * @return sync threshold value in milliseconds
     */
    public long getSyncThreshold() {
        return ensResolver.getSyncThreshold();
    }

    /**
     * This should only be used in case you need to modify the {@link EnsResolver#getSyncThreshold}
     * parameter, which dictates the threshold in milliseconds since the last processed block
     * timestamp should be to considered in sync the blockchain.
     *
     * <p>It is currently experimental and only used in ENS name resolution, but will probably be
     * made available for read calls in the future.
     *
     * @param syncThreshold the sync threshold in milliseconds
     */
    public void setSyncThreshold(long syncThreshold) {
        ensResolver.setSyncThreshold(syncThreshold);
    }

    /**
     * Return the current gas price from the yueereum node.
     *
     * <p>Note: this method was previously called {@code getGasPrice} but was renamed to distinguish
     * it when a bean accessor method on {@link Contract} was added with that name. If you have a
     * Contract subclass that is calling this method (unlikely since those classes are usually
     * generated and until very recently those generated subclasses were marked {@code final}), then
     * you will need to change your code to call this method instead, if you want the dynamic
     * behavior.
     *
     * @return the current gas price, determined dynamically at invocation
     * @throws IOException if there's a problem communicating with the yueereum node
     */
    public BigInteger requestCurrentGasPrice() throws IOException {
        YueGasPrice yueGasPrice = web3j.yueGasPrice().send();

        return yueGasPrice.getGasPrice();
    }

    protected TransactionReceipt send(
            String to, String data, BigInteger value, BigInteger gasPrice, BigInteger gasLimit)
            throws IOException, TransactionException {

        return transactionManager.executeTransaction(gasPrice, gasLimit, to, data, value);
    }

    protected TransactionReceipt send(
            String to,
            String data,
            BigInteger value,
            BigInteger gasPrice,
            BigInteger gasLimit,
            boolean constructor)
            throws IOException, TransactionException {

        return transactionManager.executeTransaction(
                gasPrice, gasLimit, to, data, value, constructor);
    }

    protected String call(String to, String data, DefaultBlockParameter defaultBlockParameter)
            throws IOException {

        return transactionManager.sendCall(to, data, defaultBlockParameter);
    }
}
