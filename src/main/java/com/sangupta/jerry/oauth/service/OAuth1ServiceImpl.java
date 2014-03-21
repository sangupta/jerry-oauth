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

package com.sangupta.jerry.oauth.service;

import com.sangupta.jerry.http.HttpHeaderName;
import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebInvoker;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.OAuthUtils;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.domain.OAuthSignatureMethod;
import com.sangupta.jerry.oauth.nonce.NonceUtils;

/**
 * Base implementation for all clients that support the OAuth 1.0 specifications.
 * 
 * @author sangupta
 * @since 1.0
 */
public abstract class OAuth1ServiceImpl implements OAuthService {
	
	/**
	 * The app specific key secret pair to be used
	 * 
	 */
	protected final KeySecretPair keySecretPair;
	
	/**
	 * Default constructor.
	 * 
	 * @param applicationKeySecretPair
	 */
	protected OAuth1ServiceImpl(KeySecretPair applicationKeySecretPair) {
		this.keySecretPair = applicationKeySecretPair;
	}
	
	/**
	 * Obtain the sign-in URL for the user - this is a two step process.
	 * In first step, we obtain the request token ourselves from the site
	 * and then send the user to sign-in url using this new token.
	 * 
	 * Note this method is expensive in I/O as this will hit the OAuth1 server
	 * end-point and obtain a request token, before providing the sign-in
	 * URL to which the user needs to be point to.
	 * 
	 */
	@Override
	public final String getLoginURL(String successUrl, String scope) {
		WebRequest request = WebInvoker.getWebRequest(getRequestTokenURL(), getRequestTokenMethod());
		
		WebForm webForm = WebForm.newForm().addParam(OAuthConstants.OAUTH_CONSUMER_KEY, this.keySecretPair.getKey())
										   .addParam(OAuthConstants.OAUTH_NONCE, NonceUtils.getUUIDNonce())
										   .addParam(OAuthConstants.OAUTH_TIMESTAMP, String.valueOf(System.currentTimeMillis()))
										   .addParam(OAuthConstants.OAUTH_VERSION, getOAuthVersion())
										   .addParam(OAuthConstants.OAUTH_SIGNATURE_METHOD, getOAuthSignatureMethod().getOauthName());
		
		// add custom parameters if they need to be added
		massageTokenRequestHeader(webForm, successUrl, scope);
		
		// generate the signature for the request
		String signature = OAuthUtils.signRequest(request, this.keySecretPair, null, getOAuthSignatureMethod(), webForm);
		
		// sign the request with the details
		
		// hit the request for request token
		
		return null;
	}

	/**
	 * Massage the token request authorization header to include any custom
	 * values that the implementation needs to pass.
	 * 
	 * @param webForm
	 *            the {@link WebForm} representation of all values inside the
	 *            header
	 * 
	 * @param successUrl
	 *            the success url that will be used for returning the request
	 * 
	 * @param scope
	 *            the scope for the request
	 */
	protected void massageTokenRequestHeader(WebForm webForm, String successUrl, String scope) {
		
	}

	/**
	 * The version number to be used in the OAuth header. The default value
	 * is {@link OAuthConstants#OAUTH_VERSION_1_0}. Implementations may override
	 * this value in case they need to pass something else.
	 * 
	 * @return
	 */
	protected String getOAuthVersion() {
		return OAuthConstants.OAUTH_VERSION_1_0;
	}
	
	/**
	 * Return the OAuth signing method name that will be used. The default
	 * value is {@link OAuthSignatureMethod#HMAC_SHA1}. Implementations may
	 * override this value in case the signing method is different.
	 * 
	 * @return
	 */
	protected OAuthSignatureMethod getOAuthSignatureMethod() {
		return OAuthSignatureMethod.HMAC_SHA1;
	}
	
	/**
	 * Obtain the end-point for obtaining the request token.
	 * 
	 * @return
	 */
	protected abstract String getRequestTokenURL();

	/**
	 * Return the HTTP verb to be used when making the request-token request. The
	 * default value is {@link WebRequestMethod#POST}. Implementations can override
	 * the value in case the HTTP verb to be used is different.
	 * 
	 * @return
	 */
	protected WebRequestMethod getRequestTokenMethod() {
		return WebRequestMethod.POST;
	}
	
	/**
	 * Return the header name to be used when sending the OAuth credentials. The
	 * default value is {@link HttpHeaderName#AUTHORIZATION}. Implementations may
	 * override the value in case the header name is different.
	 * 
	 * @return
	 */
	protected String getAuthorizationHeaderName() {
		return HttpHeaderName.AUTHORIZATION;
	}
}
