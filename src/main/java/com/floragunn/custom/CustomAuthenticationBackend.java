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
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class CustomAuthenticationBackend implements AuthenticationBackend {

	protected final Logger log = LogManager.getLogger(this.getClass());
	private final Map<String, String> users = new HashMap<>();
	private final Settings settings;
	
    public CustomAuthenticationBackend(final Settings settings, final Path configPath) {
        super();
        this.settings = settings;
        addUser("hanz_otto", "123");
        addUser("frida", "clean");
        addUser("john_doe", "itsMe");
    }

    @Override
    public String getType() {
        return "CustomAuthenticationBackend";
    }

    @Override
    public User authenticate(final AuthCredentials credentials) {
    	
    	if(!users.containsKey(credentials.getUsername())) {
    		log.trace("User {} is unknown", credentials.getUsername());
    		return null;
    	}
    	
    	byte[] pw = credentials.getPassword();
    	if(pw != null && pw.length > 0) {
    		String password = new String(pw, StandardCharsets.UTF_8);
	    	if(password.equals(users.get(credentials.getUsername()))) {
	    		return new User(credentials.getUsername(), credentials.getBackendRoles(), credentials);
	    	}
	    	else {
	    		log.trace("Login failed: password incorrect");
	    		return null;
	    	}
    	}
		log.trace("Password can not be empty");
		return null;
    }

    @Override
    public boolean exists(User user) {
        return users.containsKey(user.getName());
    }
    
    private void addUser(String name, String password) {
    	users.put(name, password);
    }

}
