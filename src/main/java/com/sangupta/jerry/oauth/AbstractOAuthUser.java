/**
 *
 * jerry-oauth : Common Java OAuth functionality
 * Copyright (c) 2012-2014, Sandeep Gupta
 * 
 * http://sangupta.com/projects/jerry-oauth
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

package com.sangupta.jerry.oauth;

/**
 * @author sangupta
 * @since 1.0
 */
public class AbstractOAuthUser implements OAuthUser {

	private final String tokenKey;
	
	private final String tokenSecret;
	
	public AbstractOAuthUser(String key, String secret) {
		this.tokenKey = key;
		this.tokenSecret = secret;
	}

	@Override
	public String getTokenKey() {
		return tokenKey;
	}

	@Override
	public String getTokenSecret() {
		return tokenSecret;
	}
	
}
