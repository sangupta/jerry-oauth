/**
 *
 * jerry - Common Java Functionality
 * Copyright (c) 2012, Sandeep Gupta
 * 
 * http://www.sangupta/projects/jerry
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.sangupta.jerry.oauth.domain;

import java.util.UUID;

/**
 * Value object to store a key-value pair that together make
 * up an {@link KeySecretPair}. The object is immutable.
 * 
 * @author sangupta
 *
 */
public class KeySecretPair {

	/**
	 * Holds the token key
	 */
	private String key;
	
	/**
	 * Holds the token secret
	 */
	private String secret;

	/**
	 * Default constructor that creates a token from the given key
	 * and secret.
	 * 
	 * @param key
	 * @param secret
	 */
	public KeySecretPair(String key, String secret) {
		this.key = key;
		this.secret = secret;
	}
	
	/**
	 * Utility method to generate a new {@link KeySecretPair} using {@link UUID}
	 * values as both key and secret.
	 * 
	 * @return
	 */
	public static KeySecretPair uuidRandomToken() {
		return new KeySecretPair(UUID.randomUUID().toString(), UUID.randomUUID().toString());
	}
	
	// Usual accessors follow

	/**
	 * @return the key
	 */
	public String getKey() {
		return key;
	}

	/**
	 * @param key the key to set
	 */
	public void setKey(String key) {
		this.key = key;
	}

	/**
	 * @return the secret
	 */
	public String getSecret() {
		return secret;
	}

	/**
	 * @param secret the secret to set
	 */
	public void setSecret(String secret) {
		this.secret = secret;
	}

}
