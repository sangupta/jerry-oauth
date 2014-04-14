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

import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;

/**
 * OAuth implementation for http://facebook.com
 * 
 * @author sangupta
 * @since 1.0
 */
public class FacebookOAuthServiceImpl extends OAuth2ServiceImpl {

	public FacebookOAuthServiceImpl(KeySecretPair keySecretPair) {
		super(keySecretPair);
	}

	@Override
	protected String getLoginEndPoint() {
		return "https://www.facebook.com/dialog/oauth";
	}

	@Override
	protected String getAuthorizationEndPoint() {
		return "https://graph.facebook.com/oauth/access_token";
	}

	/**
	 * @see com.sangupta.jerry.oauth.service.OAuth2ServiceImpl#getVerificationCodeParamName()
	 */
	@Override
	public String getVerificationCodeParamName() {
		return "code";
	}
}
