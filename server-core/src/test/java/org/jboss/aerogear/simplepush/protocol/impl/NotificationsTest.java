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
package org.jboss.aerogear.simplepush.protocol.impl;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.HashSet;
import java.util.Set;

import org.jboss.aerogear.simplepush.protocol.impl.json.JsonUtil;
import org.junit.Test;

public class NotificationsTest {

    @Test
    public void fromJson() {
        final String json = "{\"version\": 3, \"pushEndpoints\": [\"pushEndpoint1\", \"pushEndpoint2\"]}";
        System.out.println(json);
        final Notifications notifications = JsonUtil.fromJson(json, Notifications.class);
        assertThat(notifications.getVersion(), is("3"));
        assertThat(notifications.getPushEndpoints(), hasItem("pushEndpoint1"));
    }

    @Test
    public void toJson() {
        final Set<String> pushEndpoints = new HashSet<String>();
        pushEndpoints.add("firstEndpoint");
        final String json = JsonUtil.toJson(new Notifications("3",pushEndpoints));
        final Notifications notifications = JsonUtil.fromJson(json, Notifications.class);
        assertThat(notifications.getVersion(), is("3"));
        assertThat(notifications.getPushEndpoints(), hasItem("firstEndpoint"));
    }

}
