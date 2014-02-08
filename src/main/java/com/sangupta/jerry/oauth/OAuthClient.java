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

package com.sangupta.jerry.oauth;

import java.util.Map;

import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.domain.OAuthSignatureMethod;
import com.sangupta.jerry.oauth.domain.OAuthToken;

/**
 * @author sangupta
 *
 */
public class OAuthClient {

	private OAuthToken consumer;
	
	private OAuthSignatureMethod signatureMethod;
	
	private String oAuthVersion;
	
	private String authorizationHeader;
	
	private final boolean includeOAuthParamsInBody;
	
	/**
	 * Generate a new instance of {@link OAuthClient} for the given key
	 * and secret value.
	 * 
	 * @param key
	 * @param secret
	 */
	public OAuthClient(String key, String secret) {
		this(new OAuthToken(key, secret));
	}
	
	/**
	 * Generate a new instance of {@link OAuthClient} for the given {@link OAuthToken}.
	 * 
	 * @param consumer
	 */
	public OAuthClient(OAuthToken consumer) {
		this(consumer, OAuthSignatureMethod.HMAC_SHA1, OAuthConstants.OAUTH_VERSION_1_0, OAuthConstants.OAUTH_AUTHORIZATION_HEADER_NAME, false);
	}

	/**
	 * 
	 * @param consumer
	 * @param signatureMethod
	 * @param oauthVersion
	 * @param authorizationHeader
	 * @param includeOAuthParamsInBody
	 */
	public OAuthClient(OAuthToken consumer, OAuthSignatureMethod signatureMethod, String oauthVersion, String authorizationHeader, boolean includeOAuthParamsInBody) {
		this.consumer = consumer;
		this.signatureMethod = signatureMethod;
		this.oAuthVersion = oauthVersion;
		this.authorizationHeader = authorizationHeader;
		this.includeOAuthParamsInBody = includeOAuthParamsInBody;
	}
	
	/**
	 * Create a web request to the given end point for the given {@link WebRequestMethod} which has the following
	 * request parameters.
	 * 
	 * @param endPoint
	 * @param method
	 * @param requestParams
	 * @return
	 */
	public WebRequest createRequest(String endPoint, WebRequestMethod method, Map<String, String> requestParams) {
		return null;
	}
	
	/**
	 * Run an XAuth request to the given endpoint for the given credentials and
	 * generate an {@link OAuthUser} that can then be used to perform other API
	 * calls.
	 * 
	 * This call will always be a POST call.
	 * 
	 * @param userName
	 * @param password
	 */
	public OAuthUser doUserXAuth(String endPoint, String userName, String password) {
		return null;
	}
}
