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

package com.sangupta.jerry.oauth.service.impl;

import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.domain.OAuthSignatureType;
import com.sangupta.jerry.oauth.service.OAuth1ServiceImpl;
import com.sangupta.jerry.util.AssertUtils;

/**
 * OAuth implementation for http://yahoo.com
 * 
 * @author sangupta
 * @since 1.0
 */
public class YahooOAuthServiceImpl extends OAuth1ServiceImpl {

	public YahooOAuthServiceImpl(KeySecretPair applicationKeySecretPair) {
		super(applicationKeySecretPair);
	}

	@Override
	protected String getRequestTokenURL() {
		return "https://api.login.yahoo.com/oauth/v2/get_request_token";
	}
	
	@Override
	protected String getAuthenticationURL() {
		return "https://api.login.yahoo.com/oauth/v2/request_auth";
	}
	
	@Override
	protected WebRequestMethod getAuthorizationTokenMethod() {
		return WebRequestMethod.GET;
	}
	
	protected String getAuthorizationTokenURL() {
		return "https://api.login.yahoo.com/oauth/v2/get_token";
	}

	protected void massageTokenRequestHeader(WebForm webForm, String successUrl, String scope) {
		if(AssertUtils.isNotEmpty(successUrl)) {
			webForm.addParam(OAuthConstants.CALLBACK, successUrl);
		}
		
		webForm.addParam(OAuthConstants.TOKEN, "");
	}
	
	@Override
	protected void massageAuthorizationRequest(WebRequest request, WebForm webForm, KeySecretPair authTokenPair) {
		webForm.addParam(OAuthConstants.VERIFIER, authTokenPair.getSecret());
	}
	
	@Override
	protected OAuthSignatureType getOAuthSignatureType() {
		return OAuthSignatureType.QUERY_PARAMS;
	}
	
}
