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

package com.sangupta.jerry.oauth.domain;

import com.sangupta.jerry.http.WebRequestMethod;

/**
 * @author sangupta
 *
 */
public class OAuthConfig {
	
	/**
	 * The API client ID and secret to be used
	 */
	private final KeySecretPair apiKeySecretPair;
	
	/**
	 * The scope value to be used
	 */
	private String scope;
	
	/**
	 * The callback URL to be used
	 */
	private String callbackURL;
	
	/**
	 * The webrequest methods to use
	 */
	private final WebRequestMethod webRequestMethod;
	
	/**
	 * The signature method to be used by the client
	 */
	private final OAuthSignatureMethod signatureMethod;
	
	/**
	 * 
	 * @param keySecretPair
	 */
	public OAuthConfig(KeySecretPair keySecretPair) {
		this(keySecretPair, WebRequestMethod.GET, OAuthSignatureMethod.HMAC_SHA1);
	}
	
	/**
	 * 
	 * @param keySecretPair
	 * @param method
	 * @param signatureMethod
	 */
	public OAuthConfig(KeySecretPair keySecretPair, WebRequestMethod method, OAuthSignatureMethod signatureMethod) {
		this.apiKeySecretPair = keySecretPair;
		this.webRequestMethod = method;
		this.signatureMethod = signatureMethod;
	}
	
	// Usual accessors follow

	/**
	 * @return the signatureMethod
	 */
	public OAuthSignatureMethod getSignatureMethod() {
		return signatureMethod;
	}

	/**
	 * @return the apiKeySecretPair
	 */
	public KeySecretPair getApiKeySecretPair() {
		return apiKeySecretPair;
	}

	/**
	 * @return the scope
	 */
	public String getScope() {
		return scope;
	}

	/**
	 * @param scope the scope to set
	 */
	public void setScope(String scope) {
		this.scope = scope;
	}

	/**
	 * @return the callbackURL
	 */
	public String getCallbackURL() {
		return callbackURL;
	}

	/**
	 * @param callbackURL the callbackURL to set
	 */
	public void setCallbackURL(String callbackURL) {
		this.callbackURL = callbackURL;
	}

	/**
	 * @return the webRequestMethod
	 */
	public WebRequestMethod getWebRequestMethod() {
		return webRequestMethod;
	}

}
