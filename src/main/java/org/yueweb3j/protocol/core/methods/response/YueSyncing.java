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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import org.yueweb3j.protocol.ObjectMapperFactory;
import org.yueweb3j.protocol.core.Response;

/**
 * yue_syncing.
 *
 * <p>Returns an object with data about the sync status or false.
 */
public class YueSyncing extends Response<YueSyncing.Result> {

    @Override
    @JsonDeserialize(using = ResponseDeserialiser.class)
    public void setResult(Result result) {
        super.setResult(result);
    }

    public boolean isSyncing() {
        return getResult().isSyncing();
    }

    public static class Result {
        private boolean isSyncing = true;

        public Result() {}

        public boolean isSyncing() {
            return isSyncing;
        }

        public void setSyncing(boolean syncing) {
            isSyncing = syncing;
        }
    }

    @JsonIgnoreProperties({"knownStates", "pulledStates"})
    // these fields although not present in the RPC specification are returned by Geth 1.4.10
    public static class Syncing extends Result {

        private String startingBlock;
        private String currentBlock;
        private String highestBlock;
        private String knownStates;
        private String pulledStates;

        public Syncing() {}

        public Syncing(
                String startingBlock,
                String currentBlock,
                String highestBlock,
                String knownStates,
                String pulledStates) {
            this.startingBlock = startingBlock;
            this.currentBlock = currentBlock;
            this.highestBlock = highestBlock;
            this.knownStates = knownStates;
            this.pulledStates = pulledStates;
        }

        public String getStartingBlock() {
            return startingBlock;
        }

        public void setStartingBlock(String startingBlock) {
            this.startingBlock = startingBlock;
        }

        public String getCurrentBlock() {
            return currentBlock;
        }

        public void setCurrentBlock(String currentBlock) {
            this.currentBlock = currentBlock;
        }

        public String getHighestBlock() {
            return highestBlock;
        }

        public void setHighestBlock(String highestBlock) {
            this.highestBlock = highestBlock;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Syncing)) {
                return false;
            }

            Syncing syncing = (Syncing) o;

            if (isSyncing() != syncing.isSyncing()) {
                return false;
            }
            if (getStartingBlock() != null
                    ? !getStartingBlock().equals(syncing.getStartingBlock())
                    : syncing.getStartingBlock() != null) {
                return false;
            }
            if (getCurrentBlock() != null
                    ? !getCurrentBlock().equals(syncing.getCurrentBlock())
                    : syncing.getCurrentBlock() != null) {
                return false;
            }
            if (getHighestBlock() != null
                    ? !getHighestBlock().equals(syncing.getHighestBlock())
                    : syncing.getHighestBlock() != null) {
                return false;
            }
            if (knownStates != null
                    ? !knownStates.equals(syncing.knownStates)
                    : syncing.knownStates != null) {
                return false;
            }
            return pulledStates != null
                    ? pulledStates.equals(syncing.pulledStates)
                    : syncing.pulledStates == null;
        }

        @Override
        public int hashCode() {
            int result = getStartingBlock() != null ? getStartingBlock().hashCode() : 0;
            result = 31 * result + Boolean.hashCode(isSyncing());
            result = 31 * result + (getCurrentBlock() != null ? getCurrentBlock().hashCode() : 0);
            result = 31 * result + (getHighestBlock() != null ? getHighestBlock().hashCode() : 0);
            result = 31 * result + (knownStates != null ? knownStates.hashCode() : 0);
            result = 31 * result + (pulledStates != null ? pulledStates.hashCode() : 0);
            return result;
        }
    }

    public static class ResponseDeserialiser extends JsonDeserializer<Result> {

        private ObjectReader objectReader = ObjectMapperFactory.getObjectReader();

        @Override
        public Result deserialize(
                JsonParser jsonParser, DeserializationContext deserializationContext)
                throws IOException {
            Result result;
            if (jsonParser.getCurrentToken() == JsonToken.VALUE_FALSE) {
                result = new Result();
                result.setSyncing(jsonParser.getBooleanValue());
            } else {
                result = objectReader.readValue(jsonParser, Syncing.class);
            }
            return result;
        }
    }
}
