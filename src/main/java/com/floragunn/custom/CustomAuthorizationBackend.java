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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.auth.AuthorizationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class CustomAuthorizationBackend implements AuthorizationBackend {
	
	Logger log = LogManager.getLogger(this.getClass());
	private Map<String, Collection<String>> users = new HashMap<>();

    public CustomAuthorizationBackend(final Settings settings, final Path configPath) {
        super();
        addUser("hanz_otto", "admin", "boss");
        addUser("frida", "cleaner");
        addUser("john_doe", "employee", "admin");
    }

    @Override
    public String getType() {
        return "CustomAuthorizationBackend";
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials credentials) {
        if(users.containsKey(user.getName())) {
        	user.addRoles(users.get(user.getName()));
        	return;
        }
        
        log.trace("Can not add roles. User {} is unknown", user.getName());
    }
    
    private void addUser(String name, String ...roles) {
    	users.put(name, Arrays.asList(roles));
    }
}
