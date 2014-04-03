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

import java.util.Map;

import org.apache.http.entity.ContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sangupta.jerry.http.HttpHeaderName;
import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebInvoker;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.http.WebResponse;
import com.sangupta.jerry.oauth.OAuthUtils;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.domain.OAuthSignatureMethod;
import com.sangupta.jerry.oauth.extractor.TokenExtractor;
import com.sangupta.jerry.oauth.extractor.UrlParamExtractor;
import com.sangupta.jerry.oauth.nonce.NonceUtils;

/**
 * Base implementation for all clients that support the OAuth 1.0 specifications.
 * 
 * @author sangupta
 * @since 1.0
 */
public abstract class OAuth1ServiceImpl implements OAuthService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth1ServiceImpl.class);
	
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
										   .addParam(OAuthConstants.OAUTH_TIMESTAMP, String.valueOf(System.currentTimeMillis() /1000l))
										   .addParam(OAuthConstants.OAUTH_VERSION, getOAuthVersion())
										   .addParam(OAuthConstants.OAUTH_SIGNATURE_METHOD, getOAuthSignatureMethod().getOauthName());
		
		// add custom parameters if they need to be added
		massageTokenRequestHeader(webForm, successUrl, scope);
		
		// generate the signature for the request
		OAuthUtils.signRequest(request, this.keySecretPair, null, getOAuthSignatureMethod(), webForm);

		// sign the request with the details
		OAuthUtils.buildAuthorizationHeader(request, webForm, getAuthorizationHeaderName(), getAuthorizationHeaderPrefix());
		
		// hit the request for request token
		WebResponse response = WebInvoker.executeSilently(request);
		if(response == null) {
			LOGGER.error("Null response for request token API call");
			return null;
		}
		
		if(!response.isSuccess()) {
			LOGGER.debug("Unsuccessful call to request token API: {}", response.trace());
			LOGGER.debug("Response body: {}", response.getContent());
			return response.getContent();
		}
		
		Map<String, String> params = getRequestTokenExtractor().extractTokens(response.getContent());
		KeySecretPair tokenPair = new KeySecretPair(params.get("oauth_token"), params.get("oauth_token_secret"));
		
		return this.getAuthenticationURL() + "?oauth_token=" + tokenPair.getKey();
	}
	
	/**
	 * 
	 * @param tokenCode
	 * @param verifier
	 * @param redirectURL
	 * @return
	 */
	@Override
	public String getAuthorizationResponse(String tokenCode, String verifier, String redirectURL) {
		final KeySecretPair authTokenPair = new KeySecretPair(tokenCode, verifier);
		WebRequest request = WebInvoker.getWebRequest(getAuthorizationTokenURL(), getAuthorizationTokenMethod());
		
		request.bodyString("oauth_verifier=" + verifier, ContentType.APPLICATION_FORM_URLENCODED);
		
		WebForm webForm = WebForm.newForm().addParam(OAuthConstants.OAUTH_CONSUMER_KEY, this.keySecretPair.getKey())
				   .addParam(OAuthConstants.OAUTH_NONCE, NonceUtils.getUUIDNonce())
				   .addParam(OAuthConstants.OAUTH_TIMESTAMP, String.valueOf(System.currentTimeMillis() /1000l))
				   .addParam(OAuthConstants.OAUTH_VERSION, getOAuthVersion())
				   .addParam(OAuthConstants.OAUTH_TOKEN, tokenCode)
				   .addParam(OAuthConstants.OAUTH_SIGNATURE_METHOD, getOAuthSignatureMethod().getOauthName());

		// generate the signature for the request
		OAuthUtils.signRequest(request, this.keySecretPair, authTokenPair, getOAuthSignatureMethod(), webForm);
		
		// sign the request with the details
		OAuthUtils.buildAuthorizationHeader(request, webForm, getAuthorizationHeaderName(), getAuthorizationHeaderPrefix());
		
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("Making authorization call to: {}", request.trace());
		}
		
		// hit the request for request token
		WebResponse response = WebInvoker.executeSilently(request);
		if(response == null) {
			LOGGER.error("Null response for request token API call");
			return null;
		}
		
		if(!response.isSuccess()) {
			LOGGER.debug("Unsuccessful call to request token API: {}", response.trace());
			LOGGER.debug("Response body: {}", response.getContent());
			return response.getContent();
		}
		
		return response.getContent();
	}
	
	/**
	 * Specify the token extractor to be used after the request token API
	 * has been successfully called. Default is to use the {@link UrlParamExtractor}.
	 * Implementation may override the function if they wish to choose
	 * another {@link TokenExtractor} implementation.
	 * 
	 * @return
	 */
	protected TokenExtractor getRequestTokenExtractor() {
		return new UrlParamExtractor();
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
	 * Return the end-point for obtaining the authentication.
	 * 
	 * @return
	 */
	protected abstract String getAuthenticationURL();
	
	/**
	 * Return the end-point for obtaining the authorization response.
	 * 
	 * @return
	 */
	protected abstract String getAuthorizationTokenURL();

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
	
	protected WebRequestMethod getAuthorizationTokenMethod() {
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
	
	/**
	 * Return the prefix to be used in the Authorization header value. The default
	 * value is {@link OAuthConstants#OAUTH_AUTHORIZATION_HEADER_PREFIX}. Implementations
	 * may override the value in case the prefix need not be sent (in which case this should
	 * return a <code>null</code>), or a different value.
	 * 
	 * @return
	 */
	protected String getAuthorizationHeaderPrefix() {
		return OAuthConstants.OAUTH_AUTHORIZATION_HEADER_PREFIX;
	}
	
}
