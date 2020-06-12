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
package org.yueweb3j.protocol.core.filters;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

import org.yueweb3j.protocol.Web3j;
import org.yueweb3j.protocol.core.Request;
import org.yueweb3j.protocol.core.methods.response.YueFilter;
import org.yueweb3j.protocol.core.methods.response.YueLog;
import org.yueweb3j.protocol.core.methods.response.Log;

/** Log filter handler. */
public class LogFilter extends Filter<Log> {

    protected final org.yueweb3j.protocol.core.methods.request.YueFilter yueFilter;

    public LogFilter(
            Web3j web3j,
            Callback<Log> callback,
            org.yueweb3j.protocol.core.methods.request.YueFilter yueFilter) {
        super(web3j, callback);
        this.yueFilter = yueFilter;
    }

    @Override
    protected YueFilter sendRequest() throws IOException {
        return web3j.yueNewFilter(yueFilter).send();
    }

    @Override
    protected void process(List<YueLog.LogResult> logResults) {
        for (YueLog.LogResult logResult : logResults) {
            if (logResult instanceof YueLog.LogObject) {
                Log log = ((YueLog.LogObject) logResult).get();
                callback.onEvent(log);
            } else {
                throw new FilterException(
                        "Unexpected result type: " + logResult.get() + " required LogObject");
            }
        }
    }

    @Override
    protected Optional<Request<?, YueLog>> getFilterLogs(BigInteger filterId) {
        return Optional.of(web3j.yueGetFilterLogs(filterId));
    }
}
