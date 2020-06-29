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
package org.yueweb3j.protocol.pantheon;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.yueweb3j.protocol.Web3jService;
import org.yueweb3j.protocol.admin.methods.response.BooleanResponse;
import org.yueweb3j.protocol.core.DefaultBlockParameter;
import org.yueweb3j.protocol.core.Request;
import org.yueweb3j.protocol.core.methods.response.YueAccounts;
import org.yueweb3j.protocol.core.methods.response.YueGetTransactionCount;
import org.yueweb3j.protocol.core.methods.response.MinerStartResponse;
import org.yueweb3j.protocol.eea.JsonRpc2_0Eea;
import org.yueweb3j.protocol.pantheon.request.CreatePrivacyGroupRequest;
import org.yueweb3j.protocol.pantheon.response.PantheonEthAccountsMapResponse;
import org.yueweb3j.protocol.pantheon.response.PantheonFullDebugTraceResponse;
import org.yueweb3j.protocol.pantheon.response.privacy.PrivCreatePrivacyGroup;
import org.yueweb3j.protocol.pantheon.response.privacy.PrivFindPrivacyGroup;
import org.yueweb3j.protocol.pantheon.response.privacy.PrivGetPrivacyPrecompileAddress;
import org.yueweb3j.protocol.pantheon.response.privacy.PrivGetPrivateTransaction;
import org.yueweb3j.protocol.pantheon.response.privacy.PrivGetTransactionReceipt;
import org.yueweb3j.utils.Base64String;

import static java.util.Objects.requireNonNull;

public class JsonRpc2_0Pantheon extends JsonRpc2_0Eea implements Pantheon {
    public JsonRpc2_0Pantheon(Web3jService web3jService) {
        super(web3jService);
    }

    @Override
    public Request<?, MinerStartResponse> minerStart() {
        return new Request<>(
                "miner_start",
                Collections.<String>emptyList(),
                web3jService,
                MinerStartResponse.class);
    }

    @Override
    public Request<?, BooleanResponse> minerStop() {
        return new Request<>(
                "miner_stop", Collections.<String>emptyList(), web3jService, BooleanResponse.class);
    }

    @Override
    public Request<?, BooleanResponse> cliqueDiscard(String address) {
        return new Request<>(
                "clique_discard", Arrays.asList(address), web3jService, BooleanResponse.class);
    }

    @Override
    public Request<?, YueAccounts> cliqueGetSigners(DefaultBlockParameter defaultBlockParameter) {
        return new Request<>(
                "clique_getSigners",
                Arrays.asList(defaultBlockParameter.getValue()),
                web3jService,
                YueAccounts.class);
    }

    @Override
    public Request<?, YueAccounts> cliqueGetSignersAtHash(String blockHash) {
        return new Request<>(
                "clique_getSignersAtHash",
                Arrays.asList(blockHash),
                web3jService,
                YueAccounts.class);
    }

    @Override
    public Request<?, BooleanResponse> cliquePropose(String address, Boolean signerAddition) {
        return new Request<>(
                "clique_propose",
                Arrays.asList(address, signerAddition),
                web3jService,
                BooleanResponse.class);
    }

    @Override
    public Request<?, PantheonEthAccountsMapResponse> cliqueProposals() {
        return new Request<>(
                "clique_proposals",
                Collections.<String>emptyList(),
                web3jService,
                PantheonEthAccountsMapResponse.class);
    }

    @Override
    public Request<?, PantheonFullDebugTraceResponse> debugTraceTransaction(
            String transactionHash, Map<String, Boolean> options) {
        return new Request<>(
                "debug_traceTransaction",
                Arrays.asList(transactionHash, options),
                web3jService,
                PantheonFullDebugTraceResponse.class);
    }

    @Override
    public Request<?, YueGetTransactionCount> privGetTransactionCount(
            final String address, final Base64String privacyGroupId) {
        return new Request<>(
                "priv_getTransactionCount",
                Arrays.asList(address, privacyGroupId.toString()),
                web3jService,
                YueGetTransactionCount.class);
    }

    @Override
    public Request<?, PrivGetPrivateTransaction> privGetPrivateTransaction(
            final String transactionHash) {
        return new Request<>(
                "priv_getPrivateTransaction",
                Collections.singletonList(transactionHash),
                web3jService,
                PrivGetPrivateTransaction.class);
    }

    @Override
    public Request<?, PrivGetPrivacyPrecompileAddress> privGetPrivacyPrecompileAddress() {
        return new Request<>(
                "priv_getPrivacyPrecompileAddress",
                Collections.emptyList(),
                web3jService,
                PrivGetPrivacyPrecompileAddress.class);
    }

    @Override
    public Request<?, PrivCreatePrivacyGroup> privCreatePrivacyGroup(
            final List<Base64String> addresses, final String name, final String description) {
        requireNonNull(addresses);
        return new Request<>(
                "priv_createPrivacyGroup",
                Collections.singletonList(
                        new CreatePrivacyGroupRequest(addresses, name, description)),
                web3jService,
                PrivCreatePrivacyGroup.class);
    }

    @Override
    public Request<?, PrivFindPrivacyGroup> privFindPrivacyGroup(
            final List<Base64String> addresses) {
        return new Request<>(
                "priv_findPrivacyGroup",
                Collections.singletonList(addresses),
                web3jService,
                PrivFindPrivacyGroup.class);
    }

    @Override
    public Request<?, BooleanResponse> privDeletePrivacyGroup(final Base64String privacyGroupId) {
        return new Request<>(
                "priv_deletePrivacyGroup",
                Collections.singletonList(privacyGroupId.toString()),
                web3jService,
                BooleanResponse.class);
    }

    @Override
    public Request<?, PrivGetTransactionReceipt> privGetTransactionReceipt(
            final String transactionHash) {
        return new Request<>(
                "priv_getTransactionReceipt",
                Collections.singletonList(transactionHash),
                web3jService,
                PrivGetTransactionReceipt.class);
    }
}
