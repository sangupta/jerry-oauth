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

import com.sangupta.jerry.http.WebInvoker;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.KeySecretPair;

/**
 * Base implementation for all clients that support the OAuth 1.0 specifications.
 * 
 * @author sangupta
 * @since 1.0
 */
public abstract class OAuth1ServiceImpl implements OAuthService {
	
	protected final KeySecretPair keySecretPair;
	
	protected OAuth1ServiceImpl(KeySecretPair applicationKeySecretPair) {
		this.keySecretPair = applicationKeySecretPair;
	}
	
	/**
	 * Obtain the sign-in URL for the user - this is a two step process.
	 * In first step, we obtain the request token ourselves from the site
	 * and then send the user to sign-in url using this new token.
	 * 
	 * Note this method is expensive in I/O as this will hit the OAuth1 server
	 * end-point and obtain a request token, before providing the sign-in
	 * URL to which the user needs to be point to.
	 * 
	 */
	@Override
	public final String getLoginURL(String successUrl, String scope) {
		WebRequest request = WebInvoker.getWebRequest(getRequestTokenURL(), getRequestTokenMethod());
		return null;
	}

	/**
	 * Obtain the end-point for obtaining the request token.
	 * 
	 * @return
	 */
	protected abstract String getRequestTokenURL();

	/**
	 * Return the HTTP verb to be used when making the request-token request.
	 * 
	 * @return
	 */
	protected abstract WebRequestMethod getRequestTokenMethod();
	
}
