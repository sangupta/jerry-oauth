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
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;

/**
 * OAuth implementation for http://linkedin.com
 * 
 * @author sangupta
 * @since 1.0
 */
public class GithubOAuthServiceImpl extends OAuth2ServiceImpl {

	public GithubOAuthServiceImpl(KeySecretPair keySecretPair) {
		super(keySecretPair);
	}
	
	@Override
	protected String getLoginEndPoint() {
		return "https://github.com/login/oauth/authorize";
	}

	@Override
	protected String getAuthorizationEndPoint() {
		return "https://github.com/login/oauth/access_token";
	}

	@Override
	public void signRequest(WebRequest request, KeySecretPair accessPair) {
		request.addHeader(HttpHeaderName.AUTHORIZATION, "token " + accessPair.getKey());
	}
}
