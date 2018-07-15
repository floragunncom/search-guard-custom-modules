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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.user.AuthCredentials;

public class CustomHttpAuthenticator implements HTTPAuthenticator {
	
	private final Settings settings;
	private final String USERNAME_PARAM_NAME;
	private final String PASSWORD_HEADER_NAME;
	private final boolean USE_64_ENCODED_PASSWORD;
	protected final Logger log = LogManager.getLogger(this.getClass());
	
    public CustomHttpAuthenticator(final Settings settings, final Path configPath) {
    	this.settings = settings;
    	this.USERNAME_PARAM_NAME = settings.get("username_param_name", "username");
    	this.PASSWORD_HEADER_NAME = settings.get("password_header_name", "password");
    	this.USE_64_ENCODED_PASSWORD = settings.getAsBoolean("use_64_encoded_password", false);
    }

	@Override
	public String getType() {
		return "CustomHTTPAuthenticator";
	}

	@Override
	public AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws ElasticsearchSecurityException {
		
		final String username = request.hasParam(USERNAME_PARAM_NAME) ? request.param(USERNAME_PARAM_NAME) : null;
		final byte[] password;
		if(USE_64_ENCODED_PASSWORD) {
			password = Base64.getDecoder().decode(request.header(PASSWORD_HEADER_NAME));
		}
		else {
			password = request.header(PASSWORD_HEADER_NAME).getBytes(StandardCharsets.UTF_8);
		}
    	
    	if (username != null && username.length() > 0 && password != null) {
    		
    		if(password != null && password.length > 0) {
    			AuthCredentials credentials = new AuthCredentials(username, password);
	    		credentials.markComplete();
	    		return credentials;
    		}
    		else {
    			log.info("Password can not be empty");
    			return null;
    		}
    	}
		log.info("Username can not be empty");
		return null;
	}

	@Override
	public boolean reRequestAuthentication(RestChannel channel, AuthCredentials credentials) {
		final BytesRestResponse authenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED, "Unauthorized");
        channel.sendResponse(authenticateResponse);
        return true;
	}

}
