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

import static io.netty.handler.codec.http.HttpMethod.GET;
import static io.netty.handler.codec.http.HttpMethod.PUT;
import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.FORBIDDEN;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import static org.jboss.aerogear.simplepush.protocol.impl.json.JsonUtil.toJson;
import static org.jboss.aerogear.simplepush.protocol.impl.json.JsonUtil.fromJson;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.sockjs.SessionContext;
import io.netty.handler.codec.sockjs.transports.Transports;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.jboss.aerogear.simplepush.protocol.NotificationMessage;
import org.jboss.aerogear.simplepush.protocol.impl.Notifications;
import org.jboss.aerogear.simplepush.server.SimplePushServer;
import org.jboss.aerogear.simplepush.server.datastore.ChannelNotFoundException;
import org.jboss.aerogear.simplepush.util.CryptoUtil;
import org.jboss.aerogear.simplepush.util.CryptoUtil.EndpointParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles HTTP PUT 'notification' request for the SimplePush server.
 */
public class NotificationHandler extends SimpleChannelInboundHandler<Object> {

    private final UserAgents userAgents = UserAgents.getInstance();
    private final Logger logger = LoggerFactory.getLogger(NotificationHandler.class);

    private final SimplePushServer simplePushServer;
    private final ExecutorService executorService;

    public NotificationHandler(final SimplePushServer simplePushServer) {
        this.simplePushServer = simplePushServer;
        executorService = Executors.newCachedThreadPool();
    }

    @Override
    public void channelRead0(final ChannelHandlerContext ctx, final Object msg) throws Exception {
        if (msg instanceof FullHttpRequest) {
            final FullHttpRequest request = (FullHttpRequest) msg;
            final String requestUri = request.getUri();
            logger.info(requestUri);
            if (requestUri.startsWith(simplePushServer.config().endpointPrefix())) {
                handleHttpRequest(ctx, request);
            } else {
                ctx.fireChannelRead(ReferenceCountUtil.retain(msg));
            }
        } else {
            ctx.fireChannelRead(ReferenceCountUtil.retain(msg));
        }
    }

    private void handleHttpRequest(final ChannelHandlerContext ctx, final FullHttpRequest req) throws Exception {
        if (!isHttpRequestValid(req, ctx.channel())) {
            return;
        }
        executorService.submit(new Notifier(req.getUri(), req.content()));
        sendHttpResponse(OK, req, ctx.channel());
    }

    private boolean isHttpRequestValid(final FullHttpRequest request, final Channel channel) {
        if (!request.getDecoderResult().isSuccess()) {
            sendHttpResponse(BAD_REQUEST, request, channel);
            return false;
        }
        if (request.getMethod() != PUT && request.getMethod() != GET) {
            sendHttpResponse(FORBIDDEN, request, channel);
            return false;
        }
        return true;
    }

    private void sendHttpResponse(final HttpResponseStatus status, final FullHttpRequest request, final Channel channel) {
        final FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, status);
        Transports.writeContent(response, response.getStatus().toString(), Transports.CONTENT_TYPE_HTML);
        channel.writeAndFlush(response);//.addListener(ChannelFutureListener.CLOSE);
    }

    private class Notifier implements Callable<Void> {

        private final String endpoint;
        private final ByteBuf content;

        private Notifier(final String endpoint, final ByteBuf content) {
            this.endpoint = endpoint;
            this.content = content;
            this.content.retain();
        }

        @Override
        public Void call() throws Exception {
            try {
                if (endpoint.equals(simplePushServer.config().endpointPrefix())) {
                    final Notifications notifications = fromJson(content.toString(CharsetUtil.UTF_8), Notifications.class);
                    logger.info("Notifications [" + notifications + "]");
                    final String payload = "version=" + notifications.getVersion();
                    for (String pushEndpoint : notifications.getPushEndpoints()) {
                        processNotification(pushEndpoint, payload);
                    }
                } else {
                    final String pushEndpoint = endpoint.substring(endpoint.lastIndexOf('/') + 1);
                    final String payload = content.toString(CharsetUtil.UTF_8);
                    processNotification(pushEndpoint, payload);
                }
            }
            finally {
                content.release();
            }
            return null;
        }

        private void processNotification(final String pushEndpoint, final String payload) throws Exception {
            try {
                final EndpointParam endpointParam = CryptoUtil.decryptEndpoint(simplePushServer.config().tokenKey(), pushEndpoint);
                final SessionContext session = userAgents.get(endpointParam.uaid()).context();
                final NotificationMessage notification = simplePushServer.handleNotification(endpointParam.channelId(), endpointParam.uaid(), payload);
                session.send(toJson(notification));
                userAgents.updateAccessedTime(endpointParam.uaid());
            } catch (final Exception e) {
                if (e instanceof ChannelNotFoundException) {
                    final ChannelNotFoundException cne = (ChannelNotFoundException) e;
                    logger.warn("Could not find channel [" + cne.channelId() + "]");
                } else {
                    logger.debug("Error while processing notifiation:", e);
                }
            }
        }

    }

}
