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
package org.yueweb3j.protocol.core.methods.response;

import java.io.IOException;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectReader;

import org.yueweb3j.protocol.ObjectMapperFactory;
import org.yueweb3j.protocol.core.Response;

/**
 * Transaction object returned by:
 *
 * <ul>
 *   <li>yue_getTransactionByHash
 *   <li>yue_getTransactionByBlockHashAndIndex
 *   <li>yue_getTransactionByBlockNumberAndIndex
 * </ul>
 *
 * <p>This differs slightly from the request {@link YueSendTransaction} Transaction object.
 *
 * <p>See <a href="https://github.com/ethereum/wiki/wiki/JSON-RPC#yue_gettransactionbyhash">docs</a>
 * for further details.
 */
public class YueTransaction extends Response<Transaction> {

    public Optional<Transaction> getTransaction() {
        return Optional.ofNullable(getResult());
    }

    public static class ResponseDeserialiser extends JsonDeserializer<Transaction> {

        private ObjectReader objectReader = ObjectMapperFactory.getObjectReader();

        @Override
        public Transaction deserialize(
                JsonParser jsonParser, DeserializationContext deserializationContext)
                throws IOException {
            if (jsonParser.getCurrentToken() != JsonToken.VALUE_NULL) {
                return objectReader.readValue(jsonParser, Transaction.class);
            } else {
                return null; // null is wrapped by Optional in above getter
            }
        }
    }
}
