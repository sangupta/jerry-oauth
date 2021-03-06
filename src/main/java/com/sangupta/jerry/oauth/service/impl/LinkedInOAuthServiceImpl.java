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
import com.sangupta.jerry.oauth.nonce.NonceUtils;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;
import com.sangupta.jerry.util.UrlManipulator;

/**
 * OAuth implementation for http://linkedin.com
 * 
 * @author sangupta
 * @since 1.0
 */
public class LinkedInOAuthServiceImpl extends OAuth2ServiceImpl {

	public LinkedInOAuthServiceImpl(KeySecretPair keySecretPair) {
		super(keySecretPair);
	}
	
	@Override
	protected String getLoginEndPoint() {
		return "https://www.linkedin.com/uas/oauth2/authorization";
	}
	
	@Override
	protected void massageLoginURL(UrlManipulator manipulator) {
		manipulator.setQueryParam("state", NonceUtils.getNonce());
	}
	
	@Override
	protected WebRequestMethod getAuthorizationMethod() {
		return WebRequestMethod.GET;
	}

	@Override
	protected String getAuthorizationEndPoint() {
		return "https://www.linkedin.com/uas/oauth2/accessToken";
	}
	
	@Override
	protected void massageAuthorizationURL(WebForm webForm) {
		webForm.addParam(OAuthConstants.GRANT_TYPE, OAuthConstants.GRANT_AUTHORIZATION_CODE);
	}
	
	@Override
	public String signRequestUrl(String url, KeySecretPair userAccessPair) {
		UrlManipulator manipulator = new UrlManipulator(url);
		manipulator.setQueryParam("oauth2_access_token", userAccessPair.getKey());
		return manipulator.constructURL();
	}
	
	@Override
	public void signRequest(WebRequest request, KeySecretPair accessPair) {
		// do nothing
	}

}
