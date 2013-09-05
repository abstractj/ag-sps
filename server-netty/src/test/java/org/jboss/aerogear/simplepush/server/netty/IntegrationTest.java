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
package org.jboss.aerogear.simplepush.server.netty;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshakerFactory;
import io.netty.handler.codec.http.websocketx.WebSocketVersion;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.jboss.aerogear.simplepush.protocol.HelloResponse;
import org.jboss.aerogear.simplepush.protocol.MessageType;
import org.jboss.aerogear.simplepush.protocol.NotificationMessage;
import org.jboss.aerogear.simplepush.protocol.impl.HelloMessageImpl;
import org.jboss.aerogear.simplepush.protocol.impl.HelloResponseImpl;
import org.jboss.aerogear.simplepush.protocol.impl.NotificationMessageImpl;
import org.jboss.aerogear.simplepush.protocol.impl.RegisterMessageImpl;
import org.jboss.aerogear.simplepush.protocol.impl.RegisterResponseImpl;
import org.jboss.aerogear.simplepush.protocol.impl.json.JsonUtil;
import org.jboss.aerogear.simplepush.util.UUIDUtil;
import org.junit.Ignore;
import org.junit.Test;

public class IntegrationTest {

    @Test @Ignore ("intented to be run manually against an external server")
    public void notifications() throws Exception {
        final int notifications = 50;
        final URI uri = new URI("ws://kristalk4-dbevenius.rhcloud.com:8000/simplepush/websocket");
        //final URI uri = new URI("ws://localhost:7777/simplepush/websocket");
        Connection con = null;
        try {
            con = rawWebSocketConnect(uri);
            final String uaid = UUIDUtil.newUAID();
            final String json = JsonUtil.toJson(new HelloMessageImpl(uaid.toString()));
            final ChannelFuture future = con.channel().writeAndFlush(new TextWebSocketFrame(json));
            future.sync();
            final TextWebSocketFrame textFrame = con.handler().getTextFrame();
            final HelloResponse fromJson = JsonUtil.fromJson(textFrame.text(), HelloResponseImpl.class);
            assertThat(fromJson.getMessageType(), equalTo(MessageType.Type.HELLO));
            assertThat(fromJson.getUAID(), equalTo(uaid));
            textFrame.release();

            final String channelId = UUID.randomUUID().toString();
            final String register = JsonUtil.toJson(new RegisterMessageImpl(channelId));
            final ChannelFuture registerFuture = con.channel().writeAndFlush(new TextWebSocketFrame(register));
            registerFuture.sync();
            final TextWebSocketFrame registerFrame = con.handler().getTextFrame();
            final RegisterResponseImpl registerResponse = JsonUtil.fromJson(registerFrame.text(), RegisterResponseImpl.class);
            assertThat(registerResponse.getMessageType(), equalTo(MessageType.Type.REGISTER));
            assertThat(registerResponse.getChannelId(), equalTo(channelId));

            for (long i = 1; i < notifications; i++) {
                final HttpURLConnection http = getHttpConnection(new URL(registerResponse.getPushEndpoint()));
                sendVersion(i, http);
                TextWebSocketFrame notificationFrame = con.handler().getTextFrame();
                final NotificationMessage notification = JsonUtil.fromJson(notificationFrame.text(), NotificationMessageImpl.class);
                assertThat(notification.getUpdates().iterator().next().getChannelId(), equalTo(channelId));
                assertThat(notification.getUpdates().iterator().next().getVersion(), equalTo(i));
            }
            con.channel().writeAndFlush(new CloseWebSocketFrame());
            con.channel().closeFuture().sync();
        } finally {
            if (con != null) {
                con.group().shutdownGracefully();
            }
        }
    }

    private void sendVersion(final long version, final HttpURLConnection http) throws Exception {
        byte[] bytes = ("version=" + version).getBytes("UTF-8");
        http.setRequestProperty("Content-Length", String.valueOf(bytes.length));
        http.setFixedLengthStreamingMode(bytes.length);
        OutputStream out = null;
        try {
            out = http.getOutputStream();
            out.write(bytes);
            out.flush();
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }

    private Connection rawWebSocketConnect(final URI uri) throws Exception {
        final EventLoopGroup group = new NioEventLoopGroup();
        final Bootstrap b = new Bootstrap();
        final HttpHeaders customHeaders = new DefaultHttpHeaders();
        final WebSocketClientHandler handler = new WebSocketClientHandler(
                    WebSocketClientHandshakerFactory.newHandshaker(uri, WebSocketVersion.V13, null, false, customHeaders));
            b.group(group)
            .channel(NioSocketChannel.class)
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                public void initChannel(SocketChannel ch) throws Exception {
                    ChannelPipeline pipeline = ch.pipeline();
                    pipeline.addLast("http-codec", new HttpClientCodec());
                    pipeline.addLast("aggregator", new HttpObjectAggregator(8192));
                    pipeline.addLast("ws-handler", handler);
                }
            });
        final Channel ch = b.connect(uri.getHost(), uri.getPort()).sync().channel();
        handler.handshakeFuture().sync();
        return new Connection(ch, handler, group);
    }

    private HttpURLConnection getHttpConnection(final URL url) throws Exception {
        final HttpURLConnection http = (HttpURLConnection) url.openConnection();
        http.setDoOutput(true);
        http.setUseCaches(false);
        http.setRequestMethod("PUT");
        http.setRequestProperty("Content-Type", "application/json");
        if (http instanceof HttpsURLConnection) {
            setCustomTrustStore(http, "/openshift.truststore", "password");
        }
        return http;
    }

    private void setCustomTrustStore(final HttpURLConnection conn, final String trustStore, final String password) throws IOException {
        try {
            final X509TrustManager customTrustManager = getCustomTrustManager(getDefaultTrustManager(), getCustomTrustStore(trustStore, password));
            setTrustStoreForConnection((HttpsURLConnection) conn, customTrustManager);
        } catch (final Exception e) {
            throw new IOException(e);
        }
    }

    private X509TrustManager getCustomTrustManager(final X509TrustManager defaultTrustManager, final KeyStore customTrustStore)
            throws NoSuchAlgorithmException, KeyStoreException {
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(customTrustStore);
        final X509TrustManager customTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        return new DelegatingTrustManager(defaultTrustManager, customTrustManager);
    }

    private X509TrustManager getDefaultTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        final TrustManagerFactory deftmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        deftmf.init((KeyStore)null);
        final TrustManager[] trustManagers = deftmf.getTrustManagers();
        for (TrustManager trustManager : trustManagers) {
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
        }
        throw new RuntimeException("Could not find a default trustmanager");
    }

    private KeyStore getCustomTrustStore(final String trustStore, final String password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        final KeyStore customTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        customTrustStore.load(getClass().getResourceAsStream(trustStore), password.toCharArray());
        return customTrustStore;
    }

    private void setTrustStoreForConnection(final HttpsURLConnection connection, final X509TrustManager trustManager)
        throws KeyManagementException, NoSuchAlgorithmException {
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, null);
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
    }

    private class DelegatingTrustManager implements X509TrustManager {

    private final X509TrustManager delegate;
    private final X509TrustManager custom;

    public DelegatingTrustManager(final X509TrustManager delegate, final X509TrustManager custom) {
        this.delegate = delegate;
        this.custom = custom;
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        try {
            custom.checkClientTrusted(chain, authType);
        } catch (final CertificateException e) {
            delegate.checkServerTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

}

    private static class Connection {

        private final Channel channel;
        private final WebSocketClientHandler handler;
        private final EventLoopGroup group;

        public Connection(final Channel channel, final WebSocketClientHandler handler, final EventLoopGroup group) {
            this.channel = channel;
            this.handler = handler;
            this.group = group;
        }

        public Channel channel() {
            return channel;
        }

        public WebSocketClientHandler handler() {
            return handler;
        }

        public EventLoopGroup group() {
            return group;
        }

    }

}
