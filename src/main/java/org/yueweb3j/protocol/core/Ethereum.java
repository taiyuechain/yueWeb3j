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
package org.yueweb3j.protocol.core;

import java.math.BigInteger;

import org.yueweb3j.protocol.core.methods.request.ShhFilter;
import org.yueweb3j.protocol.core.methods.response.*;
import org.yueweb3j.protocol.core.methods.response.admin.AdminNodeInfo;
import org.yueweb3j.protocol.core.methods.response.admin.AdminPeers;

/** Core Ethereum JSON-RPC API. */
public interface Ethereum {
    Request<?, Web3ClientVersion> web3ClientVersion();

    Request<?, Web3Sha3> web3Sha3(String data);

    Request<?, NetVersion> netVersion();

    Request<?, NetListening> netListening();

    Request<?, NetPeerCount> netPeerCount();

    Request<?, AdminNodeInfo> adminNodeInfo();

    Request<?, AdminPeers> adminPeers();

    Request<?, YueProtocolVersion> yueProtocolVersion();

    Request<?, YueChainId> yueChainId();

    Request<?, YueCoinbase> yueCoinbase();

    Request<?, YueSyncing> yueSyncing();

    Request<?, YueMining> yueMining();

    Request<?, YueHashrate> yueHashrate();

    Request<?, YueGasPrice> yueGasPrice();

    Request<?, YueAccounts> yueAccounts();

    Request<?, YueBlockNumber> yueBlockNumber();

    Request<?, YueGetBalance> yueGetBalance(
            String address, DefaultBlockParameter defaultBlockParameter);

    Request<?, YueGetStorageAt> yueGetStorageAt(
            String address, BigInteger position, DefaultBlockParameter defaultBlockParameter);

    Request<?, YueGetTransactionCount> yueGetTransactionCount(
            String address, DefaultBlockParameter defaultBlockParameter);

    Request<?, YueGetBlockTransactionCountByHash> yueGetBlockTransactionCountByHash(
            String blockHash);

    Request<?, YueGetBlockTransactionCountByNumber> yueGetBlockTransactionCountByNumber(
            DefaultBlockParameter defaultBlockParameter);

    Request<?, YueGetUncleCountByBlockHash> yueGetUncleCountByBlockHash(String blockHash);

    Request<?, YueGetUncleCountByBlockNumber> yueGetUncleCountByBlockNumber(
            DefaultBlockParameter defaultBlockParameter);

    Request<?, YueGetCode> yueGetCode(String address, DefaultBlockParameter defaultBlockParameter);

    Request<?, YueSign> yueSign(String address, String sha3HashOfDataToSign);

    Request<?, YueSendTransaction> yueSendTransaction(
            org.yueweb3j.protocol.core.methods.request.Transaction transaction);

    Request<?, YueSendTransaction> yueSendRawTransaction(
            String signedTransactionData);

    Request<?, YueCall> yueCall(
            org.yueweb3j.protocol.core.methods.request.Transaction transaction,
            DefaultBlockParameter defaultBlockParameter);

    Request<?, YueEstimateGas> yueEstimateGas(
            org.yueweb3j.protocol.core.methods.request.Transaction transaction);

    Request<?, YueBlock> yueGetBlockByHash(String blockHash, boolean returnFullTransactionObjects);

    Request<?, YueBlock> yueGetBlockByNumber(
            DefaultBlockParameter defaultBlockParameter, boolean returnFullTransactionObjects);

    Request<?, YueTransaction> yueGetTransactionByHash(String transactionHash);

    Request<?, YueTransaction> yueGetTransactionByBlockHashAndIndex(
            String blockHash, BigInteger transactionIndex);

    Request<?, YueTransaction> yueGetTransactionByBlockNumberAndIndex(
            DefaultBlockParameter defaultBlockParameter, BigInteger transactionIndex);

    Request<?, YueGetTransactionReceipt> yueGetTransactionReceipt(String transactionHash);

    Request<?, YueBlock> yueGetUncleByBlockHashAndIndex(
            String blockHash, BigInteger transactionIndex);

    Request<?, YueBlock> yueGetUncleByBlockNumberAndIndex(
            DefaultBlockParameter defaultBlockParameter, BigInteger transactionIndex);

    Request<?, YueGetCompilers> yueGetCompilers();

    Request<?, YueCompileLLL> yueCompileLLL(String sourceCode);

    Request<?, YueCompileSolidity> yueCompileSolidity(String sourceCode);

    Request<?, YueCompileSerpent> yueCompileSerpent(String sourceCode);

    Request<?, YueFilter> yueNewFilter(org.yueweb3j.protocol.core.methods.request.YueFilter yueFilter);

    Request<?, YueFilter> yueNewBlockFilter();

    Request<?, YueFilter> yueNewPendingTransactionFilter();

    Request<?, YueUninstallFilter> yueUninstallFilter(BigInteger filterId);

    Request<?, YueLog> yueGetFilterChanges(BigInteger filterId);

    Request<?, YueLog> yueGetFilterLogs(BigInteger filterId);

    Request<?, YueLog> yueGetLogs(org.yueweb3j.protocol.core.methods.request.YueFilter yueFilter);

    Request<?, YueGetWork> yueGetWork();

    Request<?, YueSubmitWork> yueSubmitWork(String nonce, String headerPowHash, String mixDigest);

    Request<?, YueSubmitHashrate> yueSubmitHashrate(String hashrate, String clientId);

    Request<?, DbPutString> dbPutString(String databaseName, String keyName, String stringToStore);

    Request<?, DbGetString> dbGetString(String databaseName, String keyName);

    Request<?, DbPutHex> dbPutHex(String databaseName, String keyName, String dataToStore);

    Request<?, DbGetHex> dbGetHex(String databaseName, String keyName);

    Request<?, org.yueweb3j.protocol.core.methods.response.ShhPost> shhPost(
            org.yueweb3j.protocol.core.methods.request.ShhPost shhPost);

    Request<?, ShhVersion> shhVersion();

    Request<?, ShhNewIdentity> shhNewIdentity();

    Request<?, ShhHasIdentity> shhHasIdentity(String identityAddress);

    Request<?, ShhNewGroup> shhNewGroup();

    Request<?, ShhAddToGroup> shhAddToGroup(String identityAddress);

    Request<?, ShhNewFilter> shhNewFilter(ShhFilter shhFilter);

    Request<?, ShhUninstallFilter> shhUninstallFilter(BigInteger filterId);

    Request<?, ShhMessages> shhGetFilterChanges(BigInteger filterId);

    Request<?, ShhMessages> shhGetMessages(BigInteger filterId);
}
