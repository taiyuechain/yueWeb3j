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
package org.yueweb3j.protocol.core;

import io.reactivex.Flowable;
import org.yueweb3j.protocol.Web3j;
import org.yueweb3j.protocol.Web3jService;
import org.yueweb3j.protocol.core.methods.request.ShhFilter;
import org.yueweb3j.protocol.core.methods.request.ShhPost;
import org.yueweb3j.protocol.core.methods.request.Transaction;
import org.yueweb3j.protocol.core.methods.response.*;
import org.yueweb3j.protocol.rx.JsonRpc2_0Rx;
import org.yueweb3j.protocol.websocket.events.LogNotification;
import org.yueweb3j.protocol.websocket.events.NewHeadsNotification;
import org.yueweb3j.utils.Async;
import org.yueweb3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ScheduledExecutorService;

/** JSON-RPC 2.0 factory implementation. */
public class JsonRpc2_0Web3j implements Web3j {

    public static final int DEFAULT_BLOCK_TIME = 15 * 1000;

    protected final Web3jService web3jService;
    private final JsonRpc2_0Rx web3jRx;
    private final long blockTime;
    private final ScheduledExecutorService scheduledExecutorService;

    public JsonRpc2_0Web3j(Web3jService web3jService) {
        this(web3jService, DEFAULT_BLOCK_TIME, Async.defaultExecutorService());
    }

    public JsonRpc2_0Web3j(
            Web3jService web3jService,
            long pollingInterval,
            ScheduledExecutorService scheduledExecutorService) {
        this.web3jService = web3jService;
        this.web3jRx = new JsonRpc2_0Rx(this, scheduledExecutorService);
        this.blockTime = pollingInterval;
        this.scheduledExecutorService = scheduledExecutorService;
    }

    @Override
    public Request<?, Web3ClientVersion> web3ClientVersion() {
        return new Request<>(
                "web3_clientVersion",
                Collections.<String>emptyList(),
                web3jService,
                Web3ClientVersion.class);
    }

    @Override
    public Request<?, Web3Sha3> web3Sha3(String data) {
        return new Request<>("web3_sha3", Arrays.asList(data), web3jService, Web3Sha3.class);
    }

    @Override
    public Request<?, NetVersion> netVersion() {
        return new Request<>(
                "net_version", Collections.<String>emptyList(), web3jService, NetVersion.class);
    }

    @Override
    public Request<?, NetListening> netListening() {
        return new Request<>(
                "net_listening", Collections.<String>emptyList(), web3jService, NetListening.class);
    }

    @Override
    public Request<?, NetPeerCount> netPeerCount() {
        return new Request<>(
                "net_peerCount", Collections.<String>emptyList(), web3jService, NetPeerCount.class);
    }

    @Override
    public Request<?, YueProtocolVersion> yueProtocolVersion() {
        return new Request<>(
                "yue_protocolVersion",
                Collections.<String>emptyList(),
                web3jService,
                YueProtocolVersion.class);
    }

    @Override
    public Request<?, YueCoinbase> yueCoinbase() {
        return new Request<>(
                "yue_coinbase", Collections.<String>emptyList(), web3jService, YueCoinbase.class);
    }

    @Override
    public Request<?, YueSyncing> yueSyncing() {
        return new Request<>(
                "yue_syncing", Collections.<String>emptyList(), web3jService, YueSyncing.class);
    }

    @Override
    public Request<?, YueMining> yueMining() {
        return new Request<>(
                "yue_mining", Collections.<String>emptyList(), web3jService, YueMining.class);
    }

    @Override
    public Request<?, YueHashrate> yueHashrate() {
        return new Request<>(
                "yue_hashrate", Collections.<String>emptyList(), web3jService, YueHashrate.class);
    }

    @Override
    public Request<?, YueGasPrice> yueGasPrice() {
        return new Request<>(
                "yue_gasPrice", Collections.<String>emptyList(), web3jService, YueGasPrice.class);
    }

    @Override
    public Request<?, YueAccounts> yueAccounts() {
        return new Request<>(
                "yue_accounts", Collections.<String>emptyList(), web3jService, YueAccounts.class);
    }

    @Override
    public Request<?, YueBlockNumber> yueBlockNumber() {
        return new Request<>(
                "yue_blockNumber",
                Collections.<String>emptyList(),
                web3jService,
                YueBlockNumber.class);
    }

    @Override
    public Request<?, YueGetBalance> yueGetBalance(
            String address, DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "yue_getBalance",
                Arrays.asList(address, defaultBlockParameter.getValue()),
                web3jService,
                YueGetBalance.class);
    }

    @Override
    public Request<?, YueGetStorageAt> yueGetStorageAt(
            String address, BigInteger position, DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "yue_getStorageAt",
                Arrays.asList(
                        address,
                        Numeric.encodeQuantity(position),
                        defaultBlockParameter.getValue()),
                web3jService,
                YueGetStorageAt.class);
    }

    @Override
    public Request<?, YueGetTransactionCount> yueGetTransactionCount(
            String address, DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "yue_getTransactionCount",
                Arrays.asList(address, defaultBlockParameter.getValue()),
                web3jService,
                YueGetTransactionCount.class);
    }

    @Override
    public Request<?, YueGetBlockTransactionCountByHash> yueGetBlockTransactionCountByHash(
            String blockHash) {
        return new Request<>(
                "yue_getBlockTransactionCountByHash",
                Arrays.asList(blockHash),
                web3jService,
                YueGetBlockTransactionCountByHash.class);
    }

    @Override
    public Request<?, YueGetBlockTransactionCountByNumber> yueGetBlockTransactionCountByNumber(
            DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "yue_getBlockTransactionCountByNumber",
                Arrays.asList(defaultBlockParameter.getValue()),
                web3jService,
                YueGetBlockTransactionCountByNumber.class);
    }

    @Override
    public Request<?, YueGetUncleCountByBlockHash> yueGetUncleCountByBlockHash(String blockHash) {
        return new Request<>(
                "yue_getUncleCountByBlockHash",
                Arrays.asList(blockHash),
                web3jService,
                YueGetUncleCountByBlockHash.class);
    }

    @Override
    public Request<?, YueGetUncleCountByBlockNumber> yueGetUncleCountByBlockNumber(
            DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "yue_getUncleCountByBlockNumber",
                Arrays.asList(defaultBlockParameter.getValue()),
                web3jService,
                YueGetUncleCountByBlockNumber.class);
    }

    @Override
    public Request<?, YueGetCode> yueGetCode(
            String address, DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "yue_getCode",
                Arrays.asList(address, defaultBlockParameter.getValue()),
                web3jService,
                YueGetCode.class);
    }

    @Override
    public Request<?, YueSign> yueSign(String address, String sha3HashOfDataToSign) {
        return new Request<>(
                "yue_sign",
                Arrays.asList(address, sha3HashOfDataToSign),
                web3jService,
                YueSign.class);
    }

    @Override
    public Request<?, YueSendTransaction>
            yueSendTransaction(Transaction transaction) {
        return new Request<>(
                "yue_sendTransaction",
                Arrays.asList(transaction),
                web3jService,
                YueSendTransaction.class);
    }

    @Override
    public Request<?, YueSendTransaction>
            yueSendRawTransaction(String signedTransactionData) {
        return new Request<>(
                "yue_sendRawTransaction",
                Arrays.asList(signedTransactionData),
                web3jService,
                YueSendTransaction.class);
    }

    @Override
    public Request<?, YueCall> yueCall(
            Transaction transaction, DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "yue_call",
                Arrays.asList(transaction, defaultBlockParameter),
                web3jService,
                YueCall.class);
    }

    @Override
    public Request<?, YueEstimateGas> yueEstimateGas(Transaction transaction) {
        return new Request<>(
                "yue_estimateGas", Arrays.asList(transaction), web3jService, YueEstimateGas.class);
    }

    @Override
    public Request<?, YueBlock> yueGetBlockByHash(
            String blockHash, boolean returnFullTransactionObjects) {
        return new Request<>(
                "yue_getBlockByHash",
                Arrays.asList(blockHash, returnFullTransactionObjects),
                web3jService,
                YueBlock.class);
    }

    @Override
    public Request<?, YueBlock> yueGetBlockByNumber(
            DefaultBlockParameter defaultBlockParameter, boolean returnFullTransactionObjects) {
        return new Request<>(
                "yue_getBlockByNumber",
                Arrays.asList(defaultBlockParameter.getValue(), returnFullTransactionObjects),
                web3jService,
                YueBlock.class);
    }

    @Override
    public Request<?, YueTransaction> yueGetTransactionByHash(String transactionHash) {
        return new Request<>(
                "yue_getTransactionByHash",
                Arrays.asList(transactionHash),
                web3jService,
                YueTransaction.class);
    }

    @Override
    public Request<?, YueTransaction> yueGetTransactionByBlockHashAndIndex(
            String blockHash, BigInteger transactionIndex) {
        return new Request<>(
                "yue_getTransactionByBlockHashAndIndex",
                Arrays.asList(blockHash, Numeric.encodeQuantity(transactionIndex)),
                web3jService,
                YueTransaction.class);
    }

    @Override
    public Request<?, YueTransaction> yueGetTransactionByBlockNumberAndIndex(
            DefaultBlockParameter defaultBlockParameter, BigInteger transactionIndex) {
        return new Request<>(
                "yue_getTransactionByBlockNumberAndIndex",
                Arrays.asList(
                        defaultBlockParameter.getValue(), Numeric.encodeQuantity(transactionIndex)),
                web3jService,
                YueTransaction.class);
    }

    @Override
    public Request<?, YueGetTransactionReceipt> yueGetTransactionReceipt(String transactionHash) {
        return new Request<>(
                "yue_getTransactionReceipt",
                Arrays.asList(transactionHash),
                web3jService,
                YueGetTransactionReceipt.class);
    }

    @Override
    public Request<?, YueBlock> yueGetUncleByBlockHashAndIndex(
            String blockHash, BigInteger transactionIndex) {
        return new Request<>(
                "yue_getUncleByBlockHashAndIndex",
                Arrays.asList(blockHash, Numeric.encodeQuantity(transactionIndex)),
                web3jService,
                YueBlock.class);
    }

    @Override
    public Request<?, YueBlock> yueGetUncleByBlockNumberAndIndex(
            DefaultBlockParameter defaultBlockParameter, BigInteger uncleIndex) {
        return new Request<>(
                "yue_getUncleByBlockNumberAndIndex",
                Arrays.asList(defaultBlockParameter.getValue(), Numeric.encodeQuantity(uncleIndex)),
                web3jService,
                YueBlock.class);
    }

    @Override
    public Request<?, YueGetCompilers> yueGetCompilers() {
        return new Request<>(
                "yue_getCompilers",
                Collections.<String>emptyList(),
                web3jService,
                YueGetCompilers.class);
    }

    @Override
    public Request<?, YueCompileLLL> yueCompileLLL(String sourceCode) {
        return new Request<>(
                "yue_compileLLL", Arrays.asList(sourceCode), web3jService, YueCompileLLL.class);
    }

    @Override
    public Request<?, YueCompileSolidity> yueCompileSolidity(String sourceCode) {
        return new Request<>(
                "yue_compileSolidity",
                Arrays.asList(sourceCode),
                web3jService,
                YueCompileSolidity.class);
    }

    @Override
    public Request<?, YueCompileSerpent> yueCompileSerpent(String sourceCode) {
        return new Request<>(
                "yue_compileSerpent",
                Arrays.asList(sourceCode),
                web3jService,
                YueCompileSerpent.class);
    }

    @Override
    public Request<?, YueFilter> yueNewFilter(
            org.yueweb3j.protocol.core.methods.request.YueFilter yueFilter) {
        return new Request<>(
                "yue_newFilter", Arrays.asList(yueFilter), web3jService, YueFilter.class);
    }

    @Override
    public Request<?, YueFilter> yueNewBlockFilter() {
        return new Request<>(
                "yue_newBlockFilter",
                Collections.<String>emptyList(),
                web3jService,
                YueFilter.class);
    }

    @Override
    public Request<?, YueFilter> yueNewPendingTransactionFilter() {
        return new Request<>(
                "yue_newPendingTransactionFilter",
                Collections.<String>emptyList(),
                web3jService,
                YueFilter.class);
    }

    @Override
    public Request<?, YueUninstallFilter> yueUninstallFilter(BigInteger filterId) {
        return new Request<>(
                "yue_uninstallFilter",
                Arrays.asList(Numeric.toHexStringWithPrefixSafe(filterId)),
                web3jService,
                YueUninstallFilter.class);
    }

    @Override
    public Request<?, YueLog> yueGetFilterChanges(BigInteger filterId) {
        return new Request<>(
                "yue_getFilterChanges",
                Arrays.asList(Numeric.toHexStringWithPrefixSafe(filterId)),
                web3jService,
                YueLog.class);
    }

    @Override
    public Request<?, YueLog> yueGetFilterLogs(BigInteger filterId) {
        return new Request<>(
                "yue_getFilterLogs",
                Arrays.asList(Numeric.toHexStringWithPrefixSafe(filterId)),
                web3jService,
                YueLog.class);
    }

    @Override
    public Request<?, YueLog> yueGetLogs(
            org.yueweb3j.protocol.core.methods.request.YueFilter yueFilter) {
        return new Request<>("yue_getLogs", Arrays.asList(yueFilter), web3jService, YueLog.class);
    }

    @Override
    public Request<?, YueGetWork> yueGetWork() {
        return new Request<>(
                "yue_getWork", Collections.<String>emptyList(), web3jService, YueGetWork.class);
    }

    @Override
    public Request<?, YueSubmitWork> yueSubmitWork(
            String nonce, String headerPowHash, String mixDigest) {
        return new Request<>(
                "yue_submitWork",
                Arrays.asList(nonce, headerPowHash, mixDigest),
                web3jService,
                YueSubmitWork.class);
    }

    @Override
    public Request<?, YueSubmitHashrate> yueSubmitHashrate(String hashrate, String clientId) {
        return new Request<>(
                "yue_submitHashrate",
                Arrays.asList(hashrate, clientId),
                web3jService,
                YueSubmitHashrate.class);
    }

    @Override
    public Request<?, DbPutString> dbPutString(
            String databaseName, String keyName, String stringToStore) {
        return new Request<>(
                "db_putString",
                Arrays.asList(databaseName, keyName, stringToStore),
                web3jService,
                DbPutString.class);
    }

    @Override
    public Request<?, DbGetString> dbGetString(String databaseName, String keyName) {
        return new Request<>(
                "db_getString",
                Arrays.asList(databaseName, keyName),
                web3jService,
                DbGetString.class);
    }

    @Override
    public Request<?, DbPutHex> dbPutHex(String databaseName, String keyName, String dataToStore) {
        return new Request<>(
                "db_putHex",
                Arrays.asList(databaseName, keyName, dataToStore),
                web3jService,
                DbPutHex.class);
    }

    @Override
    public Request<?, DbGetHex> dbGetHex(String databaseName, String keyName) {
        return new Request<>(
                "db_getHex", Arrays.asList(databaseName, keyName), web3jService, DbGetHex.class);
    }

    @Override
    public Request<?, org.yueweb3j.protocol.core.methods.response.ShhPost> shhPost(ShhPost shhPost) {
        return new Request<>(
                "shh_post",
                Arrays.asList(shhPost),
                web3jService,
                org.yueweb3j.protocol.core.methods.response.ShhPost.class);
    }

    @Override
    public Request<?, ShhVersion> shhVersion() {
        return new Request<>(
                "shh_version", Collections.<String>emptyList(), web3jService, ShhVersion.class);
    }

    @Override
    public Request<?, ShhNewIdentity> shhNewIdentity() {
        return new Request<>(
                "shh_newIdentity",
                Collections.<String>emptyList(),
                web3jService,
                ShhNewIdentity.class);
    }

    @Override
    public Request<?, ShhHasIdentity> shhHasIdentity(String identityAddress) {
        return new Request<>(
                "shh_hasIdentity",
                Arrays.asList(identityAddress),
                web3jService,
                ShhHasIdentity.class);
    }

    @Override
    public Request<?, ShhNewGroup> shhNewGroup() {
        return new Request<>(
                "shh_newGroup", Collections.<String>emptyList(), web3jService, ShhNewGroup.class);
    }

    @Override
    public Request<?, ShhAddToGroup> shhAddToGroup(String identityAddress) {
        return new Request<>(
                "shh_addToGroup",
                Arrays.asList(identityAddress),
                web3jService,
                ShhAddToGroup.class);
    }

    @Override
    public Request<?, ShhNewFilter> shhNewFilter(ShhFilter shhFilter) {
        return new Request<>(
                "shh_newFilter", Arrays.asList(shhFilter), web3jService, ShhNewFilter.class);
    }

    @Override
    public Request<?, ShhUninstallFilter> shhUninstallFilter(BigInteger filterId) {
        return new Request<>(
                "shh_uninstallFilter",
                Arrays.asList(Numeric.toHexStringWithPrefixSafe(filterId)),
                web3jService,
                ShhUninstallFilter.class);
    }

    @Override
    public Request<?, ShhMessages> shhGetFilterChanges(BigInteger filterId) {
        return new Request<>(
                "shh_getFilterChanges",
                Arrays.asList(Numeric.toHexStringWithPrefixSafe(filterId)),
                web3jService,
                ShhMessages.class);
    }

    @Override
    public Request<?, ShhMessages> shhGetMessages(BigInteger filterId) {
        return new Request<>(
                "shh_getMessages",
                Arrays.asList(Numeric.toHexStringWithPrefixSafe(filterId)),
                web3jService,
                ShhMessages.class);
    }

    @Override
    public Request<?, YueCommittee> getCommitteeByNumber(BigInteger committeeNumber) {
        return new Request<>(
                "yue_getCommittee",
                Arrays.asList(DefaultBlockParameter.valueOf(committeeNumber).getValue()),
                web3jService,
                YueCommittee.class);
    }

    @Override
    public Request<?, YueCommitteeNumber> getCurrentCommitteeNumber() {
        return new Request<>(
                "yue_committeeNumber",
                Arrays.asList(),
                web3jService,
                YueCommitteeNumber.class);
    }

    @Override
    public Request<?, YuePermissionMembers> getListPermission(String groupAddress, int type) {
        return new Request<>(
                "cpm_listBasePermission",
                Arrays.asList(groupAddress, type),
                web3jService,
                YuePermissionMembers.class);
    }

    @Override
    public Request<?, YueMemberAddress> showWhiteList() {
        return new Request<>(
                "cpm_showWhiteList",
                Collections.<String>emptyList(),
                web3jService,
                YueMemberAddress.class);
    }

    @Override
    public Request<?, YueMemberAddress> showBlackList() {
        return new Request<>(
                "cpm_showBlackList",
                Collections.<String>emptyList(),
                web3jService,
                YueMemberAddress.class);
    }

    @Override
    public Request<?, YueMemberAddress> showMyGroup() {
        return new Request<>(
                "cpm_showMyGroup",
                Collections.<String>emptyList(),
                web3jService,
                YueMemberAddress.class);
    }

    @Override
    public Request<?, YuePermissionGroup> showGroup(String address) {
        return new Request<>(
                "cpm_showGroup",
                Collections.singletonList(address),
                web3jService,
                YuePermissionGroup.class);
    }

    @Override
    public Request<?, YueBasePermission> getListBasePermission(String address) {
        return new Request<>(
                "cpm_listBasePermission",
                Collections.singletonList(address),
                web3jService,
                YueBasePermission.class);
    }

    @Override
    public Flowable<NewHeadsNotification> newHeadsNotifications() {
        return web3jService.subscribe(
                new Request<>(
                        "yue_subscribe",
                        Collections.singletonList("newHeads"),
                        web3jService,
                        YueSubscribe.class),
                "yue_unsubscribe",
                NewHeadsNotification.class);
    }

    @Override
    public Flowable<LogNotification> logsNotifications(
            List<String> addresses, List<String> topics) {

        Map<String, Object> params = createLogsParams(addresses, topics);

        return web3jService.subscribe(
                new Request<>(
                        "yue_subscribe",
                        Arrays.asList("logs", params),
                        web3jService,
                        YueSubscribe.class),
                "yue_unsubscribe",
                LogNotification.class);
    }

    private Map<String, Object> createLogsParams(List<String> addresses, List<String> topics) {
        Map<String, Object> params = new HashMap<>();
        if (!addresses.isEmpty()) {
            params.put("address", addresses);
        }
        if (!topics.isEmpty()) {
            params.put("topics", topics);
        }
        return params;
    }

    @Override
    public Flowable<String> yueBlockHashFlowable() {
        return web3jRx.yueBlockHashFlowable(blockTime);
    }

    @Override
    public Flowable<String> yuePendingTransactionHashFlowable() {
        return web3jRx.yuePendingTransactionHashFlowable(blockTime);
    }

    @Override
    public Flowable<Log> yueLogFlowable(
            org.yueweb3j.protocol.core.methods.request.YueFilter yueFilter) {
        return web3jRx.yueLogFlowable(yueFilter, blockTime);
    }

    @Override
    public Flowable<org.yueweb3j.protocol.core.methods.response.Transaction> transactionFlowable() {
        return web3jRx.transactionFlowable(blockTime);
    }

    @Override
    public Flowable<org.yueweb3j.protocol.core.methods.response.Transaction>
            pendingTransactionFlowable() {
        return web3jRx.pendingTransactionFlowable(blockTime);
    }

    @Override
    public Flowable<YueBlock> blockFlowable(boolean fullTransactionObjects) {
        return web3jRx.blockFlowable(fullTransactionObjects, blockTime);
    }

    @Override
    public Flowable<YueBlock> replayPastBlocksFlowable(
            DefaultBlockParameter startBlock,
            DefaultBlockParameter endBlock,
            boolean fullTransactionObjects) {
        return web3jRx.replayBlocksFlowable(startBlock, endBlock, fullTransactionObjects);
    }

    @Override
    public Flowable<YueBlock> replayPastBlocksFlowable(
            DefaultBlockParameter startBlock,
            DefaultBlockParameter endBlock,
            boolean fullTransactionObjects,
            boolean ascending) {
        return web3jRx.replayBlocksFlowable(
                startBlock, endBlock, fullTransactionObjects, ascending);
    }

    @Override
    public Flowable<YueBlock> replayPastBlocksFlowable(
            DefaultBlockParameter startBlock,
            boolean fullTransactionObjects,
            Flowable<YueBlock> onCompleteFlowable) {
        return web3jRx.replayPastBlocksFlowable(
                startBlock, fullTransactionObjects, onCompleteFlowable);
    }

    @Override
    public Flowable<YueBlock> replayPastBlocksFlowable(
            DefaultBlockParameter startBlock, boolean fullTransactionObjects) {
        return web3jRx.replayPastBlocksFlowable(startBlock, fullTransactionObjects);
    }

    @Override
    public Flowable<org.yueweb3j.protocol.core.methods.response.Transaction>
            replayPastTransactionsFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        return web3jRx.replayTransactionsFlowable(startBlock, endBlock);
    }

    @Override
    public Flowable<org.yueweb3j.protocol.core.methods.response.Transaction>
            replayPastTransactionsFlowable(DefaultBlockParameter startBlock) {
        return web3jRx.replayPastTransactionsFlowable(startBlock);
    }

    @Override
    public Flowable<YueBlock> replayPastAndFutureBlocksFlowable(
            DefaultBlockParameter startBlock, boolean fullTransactionObjects) {
        return web3jRx.replayPastAndFutureBlocksFlowable(
                startBlock, fullTransactionObjects, blockTime);
    }

    @Override
    public Flowable<org.yueweb3j.protocol.core.methods.response.Transaction>
            replayPastAndFutureTransactionsFlowable(DefaultBlockParameter startBlock) {
        return web3jRx.replayPastAndFutureTransactionsFlowable(startBlock, blockTime);
    }

    @Override
    public void shutdown() {
        scheduledExecutorService.shutdown();
        try {
            web3jService.close();
        } catch (IOException e) {
            throw new RuntimeException("Failed to close web3j service", e);
        }
    }

    @Override
    public BatchRequest newBatch() {
        return null;
    }
}
