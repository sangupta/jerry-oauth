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

package com.sangupta.jerry.oauth.token;

import com.sangupta.jerry.oauth.domain.KeySecretPair;

/**
 * Contract for implementations that wish to generate OAuth tokens
 * for users.
 * 
 * @author sangupta
 *
 */
public interface OAuthTokenGenerator {
	
	/**
	 * For the given consumer key, generate a new OAuth token pair
	 * that needs to be sent to the client.
	 * 
	 * @param consumerKey
	 * @return
	 */
	public KeySecretPair generateKeyPair(String consumerKey);
	
	/**
	 * Return the token secret for the given consumer key and access token.
	 * The method should return a <code>null</code> if any of the consumer
	 * key or the request token do not match.
	 * 
	 * @param consumerKey
	 * @param accessToken
	 * @return
	 */
	public String getSecret(String consumerKey, String requestToken);

}
