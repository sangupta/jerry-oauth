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

import org.apache.http.entity.ContentType;

import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.domain.TokenAndUrl;
import com.sangupta.jerry.oauth.service.OAuth1ServiceImpl;
import com.sangupta.jerry.util.AssertUtils;

/**
 * OAuth implementation for http://twitter.com
 * 
 * @author sangupta
 * @since 1.0
 */
public class TwitterOAuthServiceImpl extends OAuth1ServiceImpl {

	public TwitterOAuthServiceImpl(KeySecretPair applicationKeySecretPair) {
		super(applicationKeySecretPair);
	}

	@Override
	protected String getRequestTokenURL() {
		return "https://api.twitter.com/oauth/request_token";
	}
	
	@Override
	protected String getAuthenticationURL() {
		return "https://api.twitter.com/oauth/authenticate";
	}
	
	protected String getAuthorizationTokenURL() {
		return "https://api.twitter.com/oauth/access_token";
	}

	protected void massageTokenRequestHeader(WebForm webForm, String successUrl, String scope) {
		if(AssertUtils.isNotEmpty(successUrl)) {
			webForm.addParam(OAuthConstants.CALLBACK, successUrl);
		}
		
		webForm.addParam(OAuthConstants.TOKEN, "");
	}

	@Override
	protected void massageAuthorizationRequest(WebRequest request, WebForm webForm, TokenAndUrl tokenAndUrl, String verifier) {
		request.bodyString(OAuthConstants.VERIFIER + "=" + verifier, ContentType.APPLICATION_FORM_URLENCODED);
	}
	
}
