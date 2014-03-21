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

import com.sangupta.jerry.http.HttpHeaderName;
import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;
import com.sangupta.jerry.util.AssertUtils;
import com.sangupta.jerry.util.UrlManipulator;

/**
 * 
 * @author sangupta
 * @since 1.0
 */
public class GoogleOAuthServiceImpl extends OAuth2ServiceImpl {
	
	public static final String END_POINT = "https://accounts.google.com/o/oauth2/auth";
	
	public static final String AUTH_END_POINT = "https://accounts.google.com/o/oauth2/token";
	
	private String loginHint = null;
	
	public GoogleOAuthServiceImpl(KeySecretPair keySecretPair) {
		super(keySecretPair);
	}

	@Override
	protected void massageLoginURL(UrlManipulator um) {
		um.setQueryParam("access_type", "online");
		um.setQueryParam("approval_prompt", "auto");
		
		if(AssertUtils.isNotBlank(this.loginHint)) {
			um.setQueryParam("login_hint", this.loginHint);
		}
		um.setQueryParam("include_granted_scopes", "false");
	}

	@Override
	protected String getLoginEndPoint() {
		return END_POINT;
	}

	public void setLoginHint(String loginHint) {
		this.loginHint = loginHint;
	}

	@Override
	protected String getAuthorizationEndPoint() {
		return AUTH_END_POINT;
	}

	@Override
	protected WebRequestMethod getAuthorizationMethod() {
		return WebRequestMethod.POST;
	}

	@Override
	public void signRequest(WebRequest request, KeySecretPair accessPair) {
		request.addHeader(HttpHeaderName.AUTHORIZATION, "Bearer " + accessPair.getKey());
	}

	@Override
	protected void massageAuthorizationURL(WebForm webForm) {
		webForm.addParam("grant_type", "authorization_code");
	}
	
}
