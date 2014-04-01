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

package com.sangupta.jerry.oauth.service;

import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.oauth.domain.KeySecretPair;

/**
 * Base contract for all OAuth based services: 1.0, 2.0 or hybrid. Decouples
 * the callee from the actual implementation to be used.
 * 
 * @author sangupta
 * @since 1.0
 */
public interface OAuthService {
	
	/**
	 * Get the authentication URL that the user needs to be redirected to.
	 * 
	 * @param successUrl
	 *            the callback success url that the call will come back to
	 * 
	 * @param scope
	 *            the scopes to be used for authentication
	 * 
	 * @return the login url to which the user should be redirected
	 * 
	 */
	public String getLoginURL(String successUrl, String scope);
	
	/**
	 * Sign the given request using the given access pair.
	 * 
	 * @param request
	 * @param accessPair
	 */
	public void signRequest(WebRequest request, KeySecretPair accessPair);
	
}
