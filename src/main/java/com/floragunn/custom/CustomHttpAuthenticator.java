/*
 * Copyright 2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
package com.floragunn.custom;

import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.user.AuthCredentials;

public class CustomHttpAuthenticator implements HTTPAuthenticator {
	
	private final Settings settings;
	
    public CustomHttpAuthenticator(final Settings settings, final Path configPath) {
    	this.settings = settings;
    }

	@Override
	public String getType() {
		return "CustomHTTPAuthenticator";
	}

	@Override
	public AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws ElasticsearchSecurityException {
		
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AuthCredentials creds = AccessController.doPrivileged(new PrivilegedAction<AuthCredentials>() {
            @Override
            public AuthCredentials run() {                        
            	String username = request.param("username");
            	if (username != null && username.length() > 0) {
            		return new AuthCredentials(username, new String[0]);	
            	}
            	else {
            		return null;
            	}
            }
        });
        
        return creds;
		
	}

	@Override
	public boolean reRequestAuthentication(RestChannel channel, AuthCredentials credentials) {
		// needed for challenging, e.g. Basic Authentication or Kerberos. Not needed here.
		return false;
	}

}
