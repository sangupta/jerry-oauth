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
 * Constants with regards to OAuth workflows.
 * 
 * @author sangupta
 * @since 1.0
 */
public interface OAuthConstants {
	
	public static final String SIGNATURE = "oauth_signature";
	
	public static final String CONSUMER_KEY = "oauth_consumer_key";
	
	public static final String TOKEN = "oauth_token";
	
	public static final String SIGNATURE_METHOD = "oauth_signature_method";
	
	public static final String TIMESTAMP = "oauth_timestamp";
	
	public static final String NONCE = "oauth_nonce";
	
	public static final String VERSION = "oauth_version";
	
	public static final String VERSION_1_0 = "1.0";
	
	public static final String OAUTH_AUTHORIZATION_HEADER_PREFIX = "OAuth";
	
	// XAuth
	
	public static final String X_AUTH_MODE = "x_auth_mode";
	
	public static final String X_AUTH_USERNAME = "x_auth_username";
	
	public static final String X_AUTH_PASSWORD = "x_auth_password";
	
	public static final String DEFAULT_XAUTH_MODE = "client_auth";

	// OAuth 2.0
	
	public static final String VERSION_2_0 = "1.0";

	public static final String ACCESS_TOKEN = "access_token";

	public static final String CLIENT_ID = "client_id";
	
	public static final String CLIENT_SECRET = "client_secret";

	public static final String REDIRECT_URI = "redirect_uri";

	public static final String CODE = "code";
	
	public static final String SCOPE = "scope";
	
	public static final String OUT_OF_BAND = "oob";
	
	public static final String VERIFIER = "oauth_verifier";
	
	public static final String CALLBACK = "oauth_callback";
	
	public static final String GRANT_TYPE = "grant_type";
	
	public static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
	
}
