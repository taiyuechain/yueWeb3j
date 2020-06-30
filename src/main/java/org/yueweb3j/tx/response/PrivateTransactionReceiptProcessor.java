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
package org.yueweb3j.tx.response;

import java.io.IOException;
import java.util.Optional;

import org.yueweb3j.protocol.exceptions.TransactionException;
import org.yueweb3j.protocol.pantheon.Pantheon;
import org.yueweb3j.protocol.pantheon.response.privacy.PrivGetTransactionReceipt;
import org.yueweb3j.protocol.pantheon.response.privacy.PrivateTransactionReceipt;

public abstract class PrivateTransactionReceiptProcessor extends TransactionReceiptProcessor {
    private Pantheon pantheon;

    public PrivateTransactionReceiptProcessor(Pantheon pantheon) {
        super(pantheon);
        this.pantheon = pantheon;
    }

    @Override
    Optional<PrivateTransactionReceipt> sendTransactionReceiptRequest(String transactionHash)
            throws IOException, TransactionException {
        PrivGetTransactionReceipt transactionReceipt =
                pantheon.privGetTransactionReceipt(transactionHash).send();
        if (transactionReceipt.hasError()) {
            throw new TransactionException(
                    "Error processing request: " + transactionReceipt.getError().getMessage());
        }

        return transactionReceipt.getTransactionReceipt();
    }
}