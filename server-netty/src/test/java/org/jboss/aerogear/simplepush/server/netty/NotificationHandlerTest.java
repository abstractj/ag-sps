/**
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.aerogear.simplepush.server.netty;

import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.sockjs.SessionContext;
import io.netty.util.CharsetUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

import org.jboss.aerogear.simplepush.protocol.MessageType;
import org.jboss.aerogear.simplepush.protocol.RegisterResponse;
import org.jboss.aerogear.simplepush.protocol.impl.NotificationMessageImpl;
import org.jboss.aerogear.simplepush.protocol.impl.Notifications;
import org.jboss.aerogear.simplepush.protocol.impl.RegisterMessageImpl;
import org.jboss.aerogear.simplepush.protocol.impl.json.JsonUtil;
import org.jboss.aerogear.simplepush.server.DefaultSimplePushServer;
import org.jboss.aerogear.simplepush.server.DefaultSimplePushConfig;
import org.jboss.aerogear.simplepush.server.SimplePushServer;
import org.jboss.aerogear.simplepush.server.datastore.InMemoryDataStore;
import org.jboss.aerogear.simplepush.util.CryptoUtil;
import org.jboss.aerogear.simplepush.util.UUIDUtil;
import org.junit.Test;

public class NotificationHandlerTest {

    @Test
    public void notification() throws Exception {
        final String uaid = UUIDUtil.newUAID();
        final String channelId = UUID.randomUUID().toString();
        final SimplePushServer simplePushServer = defaultPushServer();
        final EmbeddedChannel channel = createWebsocketChannel(simplePushServer);
        registerUserAgent(uaid, channel);
        doRegister(channelId, uaid, simplePushServer);
        doNotification(channelId, uaid, simplePushServer.config().tokenKey(), 1L, channel);
        channel.close();
    }

    @Test
    public void notificationVersionEqualToCurrentVersion() throws Exception {
        final String uaid = UUIDUtil.newUAID();
        final String channelId = UUID.randomUUID().toString();
        final SimplePushServer simplePushServer = defaultPushServer();
        final EmbeddedChannel channel = createWebsocketChannel(simplePushServer);
        registerUserAgent(uaid, channel);
        doRegister(channelId, uaid, simplePushServer);
        doNotification(channelId, uaid, simplePushServer.config().tokenKey(), 1L, channel);

        final HttpResponse response = sendNotification(channelId, uaid, 1L, simplePushServer);
        assertThat(response.getStatus(), is(HttpResponseStatus.OK));
        channel.close();
    }

    @Test
    public void notificationVersionLessThanCurrent() throws Exception {
        final String uaid = UUIDUtil.newUAID();
        final String channelId = UUID.randomUUID().toString();
        final SimplePushServer simplePushServer = defaultPushServer();
        final EmbeddedChannel channel = createWebsocketChannel(simplePushServer);
        registerUserAgent(uaid, channel);
        doRegister(channelId, uaid, simplePushServer);
        doNotification(channelId, uaid, simplePushServer.config().tokenKey(), 10L, channel);

        final HttpResponse response = sendNotification(channelId, uaid, 9L, simplePushServer);
        assertThat(response.getStatus(), is(HttpResponseStatus.OK));
        channel.close();
    }

    @Test
    public void notificationWithNonExistingChannelId() throws Exception {
        final String uaid = UUIDUtil.newUAID();
        final SimplePushServer simplePushServer = defaultPushServer();
        final EmbeddedChannel channel = createWebsocketChannel(simplePushServer);
        channel.writeInbound(notificationRequest("non-existing-channelId", uaid, simplePushServer.config().tokenKey(), 10L));
        final HttpResponse httpResponse = (HttpResponse) channel.readOutbound();
        assertThat(httpResponse.getStatus().code(), equalTo(200));
        channel.close();
    }

    @Test
    public void notificationNonExistingUserAgentId() throws Exception {
        final String uaid = UUIDUtil.newUAID();
        final String channelId = UUID.randomUUID().toString();
        final SimplePushServer simplePushServer = defaultPushServer();
        final EmbeddedChannel channel = createWebsocketChannel(simplePushServer);
        doRegister(channelId, uaid, simplePushServer);
        doNotificationNonExistingUaid(channelId, uaid, simplePushServer.config().tokenKey(), 1L, channel);
        channel.close();
    }

    @Test
    public void notifications() throws Exception {
        final String uaid = UUIDUtil.newUAID();
        final String channelId1 = UUID.randomUUID().toString();
        final String channelId2 = UUID.randomUUID().toString();
        final SimplePushServer simplePushServer = defaultPushServer();
        final EmbeddedChannel channel = createWebsocketChannel(simplePushServer);
        registerUserAgent(uaid, channel);
        doRegister(channelId1, uaid, simplePushServer);
        doRegister(channelId2, uaid, simplePushServer);

        final Set<String> pushEndpoints = new HashSet<String>();
        pushEndpoints.add(CryptoUtil.encrypt(simplePushServer.config().tokenKey(), uaid + "." + channelId1));
        pushEndpoints.add(CryptoUtil.encrypt(simplePushServer.config().tokenKey(), uaid + "." + channelId2));
        doNotifications(pushEndpoints, uaid, simplePushServer.config().tokenKey(), 1L, channel);
    }

    private SimplePushServer defaultPushServer() {
        return new DefaultSimplePushServer(new InMemoryDataStore(), DefaultSimplePushConfig.defaultConfig());
    }

    private HttpResponse sendNotification(final String channelId, final String uaid, final long version, final SimplePushServer simplePushServer) throws Exception {
        final EmbeddedChannel ch = createWebsocketChannel(simplePushServer);
        ch.writeInbound(notificationRequest(channelId, uaid, simplePushServer.config().tokenKey(), 9L));
        return (HttpResponse) ch.readOutbound();
    }

    private void registerUserAgent(final String uaid, final EmbeddedChannel ch) {
        UserAgents.getInstance().add(uaid, channelSession(ch));
    }

    private RegisterResponse doRegister(final String channelId, final String uaid, final SimplePushServer server) throws Exception {
        return server.handleRegister(new RegisterMessageImpl(channelId), uaid);
    }

    private FullHttpRequest notificationRequest(final String channelId, final String uaid, final byte[] tokenKey, final Long version) throws Exception {
        final String encrypted = CryptoUtil.encrypt(tokenKey, uaid + "." + channelId);
        final FullHttpRequest req = new DefaultFullHttpRequest(HTTP_1_1, HttpMethod.PUT, "/update/" + encrypted);
        req.content().writeBytes(Unpooled.copiedBuffer("version=" + version.toString(), CharsetUtil.UTF_8));
        return req;
    }

    private FullHttpRequest notificationRequests(final Set<String> endpoints, final String uaid, final byte[] tokenKey, final Long version) throws Exception {
        final FullHttpRequest req = new DefaultFullHttpRequest(HTTP_1_1, HttpMethod.PUT, "/update");
        final String json = JsonUtil.toJson(new Notifications(String.valueOf(version), endpoints));
        req.content().writeBytes(Unpooled.copiedBuffer(json.toString(), CharsetUtil.UTF_8));
        return req;
    }

    private HttpResponse doNotification(final String channelId, final String uaid, final byte[] tokenKey,
            final Long version, final EmbeddedChannel channel) throws Exception {
        HttpResponse httpResponse = null;
        channel.writeInbound(notificationRequest(channelId, uaid, tokenKey, version));

        // The response to the client that sent the notification request
        final CountDownLatch countDownLatch = new CountDownLatch(2);
        final List<Object> readObjects = new ArrayList<Object>();
        while (countDownLatch.getCount() != 2) {
            final Object o = channel.readOutbound();
            if (o == null) {
                Thread.sleep(200);
            } else {
                readObjects.add(o);
                countDownLatch.countDown();
            }
        }
        for (Object object : readObjects) {
            if (object instanceof HttpResponse) {
                httpResponse = (HttpResponse) object;
                assertThat(httpResponse.getStatus().code(), equalTo(200));
            } else {
                // The notification destined for the connected channel
                final NotificationMessageImpl notification = responseToType(object, NotificationMessageImpl.class);
                assertThat(notification.getMessageType(), is(MessageType.Type.NOTIFICATION));
                assertThat(notification.getUpdates().size(), is(1));
                assertThat(notification.getUpdates().iterator().next().getChannelId(), equalTo(channelId));
                assertThat(notification.getUpdates().iterator().next().getVersion(), equalTo(version));
            }
        }
        return httpResponse;
    }

    private HttpResponse doNotifications(final Set<String> endpoints, final String uaid, final byte[] tokenKey,
            final Long version, final EmbeddedChannel channel) throws Exception {
        HttpResponse httpResponse = null;
        channel.writeInbound(notificationRequests(endpoints, uaid, tokenKey, version));

        // The response to the client that sent the notification request
        final CountDownLatch countDownLatch = new CountDownLatch(2);
        final List<Object> readObjects = new ArrayList<Object>();
        while (countDownLatch.getCount() != 2) {
            final Object o = channel.readOutbound();
            if (o == null) {
                Thread.sleep(200);
            } else {
                readObjects.add(o);
                countDownLatch.countDown();
            }
        }
        for (Object object : readObjects) {
            if (object instanceof HttpResponse) {
                httpResponse = (HttpResponse) object;
                assertThat(httpResponse.getStatus().code(), equalTo(200));
            } else {
                // The notification destined for the connected channel
                final NotificationMessageImpl notification = responseToType(object, NotificationMessageImpl.class);
                assertThat(notification.getMessageType(), is(MessageType.Type.NOTIFICATION));
                assertThat(notification.getUpdates().size(), is(1));
                //assertThat(notification.getUpdates().iterator().next().getChannelId(), equalTo(channelId));
                assertThat(notification.getUpdates().iterator().next().getVersion(), equalTo(version));
            }
        }
        return httpResponse;
    }

    private HttpResponse doNotificationNonExistingUaid(final String channelId, final String uaid, final byte[] tokenKey,
            final Long version, final EmbeddedChannel channel) throws Exception {
        channel.writeInbound(notificationRequest(channelId, uaid, tokenKey, version));
        final HttpResponse httpResponse = (HttpResponse) channel.readOutbound();
        assertThat(httpResponse.getStatus().code(), equalTo(200));
        return httpResponse;
    }

    private <T> T responseToType(final Object response, Class<T> type) {
        if (response instanceof String) {
            return JsonUtil.fromJson((String) response, type);
        }
        throw new IllegalArgumentException("Response is expected to be of type TextWebSocketFrame was: " + response);
    }

    private EmbeddedChannel createWebsocketChannel(SimplePushServer simplePushServer) throws Exception {
        return new EmbeddedChannel(new NotificationHandler(simplePushServer));
    }

    private SessionContext channelSession(final EmbeddedChannel ch) {
        return new SessionContext() {
            @Override
            public void send(String message) {
                ch.writeOutbound(message);
            }

            @Override
            public void close() {
                ch.close();
            }

            @Override
            public ChannelHandlerContext getContext() {
                return null;
            }
        };
    }

}
