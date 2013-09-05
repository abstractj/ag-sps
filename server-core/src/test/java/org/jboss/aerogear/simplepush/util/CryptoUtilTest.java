/**
 * JBoss, Home of Professional Open Source Copyright Red Hat, Inc., and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
package org.jboss.aerogear.simplepush.util;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.jboss.aerogear.simplepush.util.CryptoUtil.EndpointParam;
import org.junit.Ignore;
import org.junit.Test;

public class CryptoUtilTest {

    @Test
    public void encrypt() throws Exception {
        final byte[] key = CryptoUtil.secretKey("key");
        final String encrypted = CryptoUtil.encrypt(key, "some string to endrypt");
        assertThat(encrypted, is(notNullValue()));
    }

    @Test
    public void decrypt() throws Exception {
        final byte[] key = CryptoUtil.secretKey("key");
        final String expected = UUID.randomUUID().toString() + "." + UUID.randomUUID().toString();
        final String encrypted = CryptoUtil.encrypt(key, expected);
        assertThat(CryptoUtil.decrypt(key, encrypted), is(equalTo(expected)));
    }

    @Test
    public void decryptEndpoint() throws Exception {
        final byte[] key = CryptoUtil.secretKey("key");
        final String uaid = UUID.randomUUID().toString();
        final String channelId = UUID.randomUUID().toString();
        final String encrypted = CryptoUtil.encrypt(key, uaid + "." + channelId);
        final EndpointParam endpointParam = CryptoUtil.decryptEndpoint(key, encrypted);
        assertThat(endpointParam.uaid(), is(equalTo(uaid)));
        assertThat(endpointParam.channelId(), is(equalTo(channelId)));
    }

    @Test @Ignore ("intended to be run manually")
    public void performance() throws Exception {
        final byte[] key = CryptoUtil.randomKey(128);
        final String clearText = UUID.randomUUID().toString() + "." + UUID.randomUUID().toString();
        System.out.println("Warm up start");
        encryptDecrypt(100000L, key, clearText);
        System.out.println("Warm up done");
        System.out.println("Performance test start");
        encryptDecrypt(100000L, key, clearText);
        System.out.println("Performance test done");
    }

    private void encryptDecrypt(final long times, final byte[] key, final String clearText) throws Exception {
        final long startTime = System.nanoTime();
        for (int i = 0; i < times; i++) {
            final String encrypted = CryptoUtil.encrypt(key, clearText);
            final String decrypted = CryptoUtil.decrypt(key, encrypted);
        }
        long elapsedTime = System.nanoTime() - startTime;
        System.out.println("Elapsed nanoseconds " + elapsedTime + " for " + times + " encryptions/decryptions");
        long millis = TimeUnit.NANOSECONDS.toMillis(elapsedTime);
        System.out.println("Elapsed milliseconds " + millis + " for " + times + " encryptions/decryptions");
        System.out.println("Elapsed nanoseconds per encrypt/decrypt " + elapsedTime/times);
    }

}
