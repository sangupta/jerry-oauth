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


/**
 * Value object that may contain a request token and the authentication
 * URL to which the user needs to be redirected to for OAuth workflows.
 * 
 * @author sangupta
 * @since 1.0
 */
public class TokenAndUrl {

	/**
	 * The {@link KeySecretPair} request token associated with this request.
	 * 
	 */
	public transient final KeySecretPair token;
	
	/**
	 * The callback URL to which the application is redirected after successful
	 * authentication
	 */
	public transient final String callbackURL;
	
	/**
	 * The redirect login URL that the client needs to use
	 */
	public transient final String loginRedirectURL;
	
	public TokenAndUrl(String loginRedirectURL, String callbackURL) {
		this.loginRedirectURL = loginRedirectURL;
		this.callbackURL = callbackURL;
		this.token = null;
	}
	
	public TokenAndUrl(String loginRedirectURL, String callbackURL, KeySecretPair token) {
		this.loginRedirectURL = loginRedirectURL;
		this.callbackURL = callbackURL;
		this.token = token;
	}

	@Override
	public String toString() {
		return this.loginRedirectURL;
	}
	
}
