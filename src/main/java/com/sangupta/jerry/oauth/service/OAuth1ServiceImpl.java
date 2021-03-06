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

import org.apache.http.NameValuePair;
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
import com.sangupta.jerry.oauth.domain.OAuthSignatureType;
import com.sangupta.jerry.oauth.domain.TokenAndUrl;
import com.sangupta.jerry.oauth.extractor.TokenExtractor;
import com.sangupta.jerry.oauth.extractor.UrlParamTokenExtractor;
import com.sangupta.jerry.oauth.nonce.NonceUtils;
import com.sangupta.jerry.util.UrlManipulator;

/**
 * Base implementation for all clients that support the OAuth 1.0 specifications.
 * 
 * @author sangupta
 * @since 1.0
 */
public abstract class OAuth1ServiceImpl implements OAuthService {
	
	/**
	 * My logger instance
	 */
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
	
	public String getAccessTokenParamName() {
		return OAuthConstants.TOKEN;
	}
	
	public String getAccessTokenSecretParamName() {
		return OAuthConstants.TOKEN_SECRET;
	}
	
	public String getRefreshTokenParamName() {
		return null;
	}
	
	public String getAccessTokenExpiryParamName() {
		return null;
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
	public final TokenAndUrl getLoginURL(String successUrl, String scope) {
		WebRequest request = WebInvoker.getWebRequest(getRequestTokenURL(), getRequestTokenMethod());
		
		WebForm webForm = WebForm.newForm().addParam(OAuthConstants.CONSUMER_KEY, this.keySecretPair.getKey())
										   .addParam(OAuthConstants.NONCE, NonceUtils.getNonce())
										   .addParam(OAuthConstants.TIMESTAMP, String.valueOf(System.currentTimeMillis() /1000l))
										   .addParam(OAuthConstants.VERSION, getOAuthVersion())
										   .addParam(OAuthConstants.SIGNATURE_METHOD, getOAuthSignatureMethod().getOAuthName());
		
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
			return null;
		}
		
		Map<String, String> params = getRequestTokenExtractor().extractTokens(response.getContent());
		KeySecretPair tokenPair = new KeySecretPair(params.get("oauth_token"), params.get("oauth_token_secret"));
		
		return new TokenAndUrl(this.getAuthenticationURL() + "?oauth_token=" + tokenPair.getKey(), successUrl, tokenPair);
	}
	
	@Override
	public String signRequestUrl(String url, KeySecretPair userAccessPair) {
		return url;
	}
	
	@Override
	public void signRequest(WebRequest request, KeySecretPair userAccessPair) {
		if(request == null) {
			throw new IllegalArgumentException("WebRequest to be signed cannot be null");
		}
		
		WebForm webForm = WebForm.newForm().addParam(OAuthConstants.CONSUMER_KEY, this.keySecretPair.getKey())
				   .addParam(OAuthConstants.NONCE, NonceUtils.getNonce())
				   .addParam(OAuthConstants.TIMESTAMP, String.valueOf(System.currentTimeMillis() /1000l))
				   .addParam(OAuthConstants.VERSION, getOAuthVersion())
				   .addParam(OAuthConstants.SIGNATURE_METHOD, getOAuthSignatureMethod().getOAuthName());
		
		if(userAccessPair != null) {
			webForm.addParam(OAuthConstants.TOKEN, userAccessPair.getKey());
		}
		
		addCustomOAuthParamsDuringSigning(webForm);
		
		// generate the signature for the request
		OAuthUtils.signRequest(request, this.keySecretPair, userAccessPair, getOAuthSignatureMethod(), webForm);
		
		// sign the request with the details
		OAuthUtils.buildAuthorizationHeader(request, webForm, getAuthorizationHeaderName(), getAuthorizationHeaderPrefix());
	}

	/**
	 * Add custom OAuth parameters during the signing phase.
	 * 
	 * @param webForm
	 */
	protected void addCustomOAuthParamsDuringSigning(WebForm webForm) {
		
	}

	/**
	 * 
	 * @param tokenCode
	 * @param verifier
	 * @param redirectURL
	 * @return
	 */
	@Override
	public String getAuthorizationResponse(TokenAndUrl tokenAndUrl, String verifier) {
		WebRequest request = WebInvoker.getWebRequest(getAuthorizationTokenURL(), getAuthorizationTokenMethod());
		
		WebForm webForm = WebForm.newForm().addParam(OAuthConstants.CONSUMER_KEY, this.keySecretPair.getKey())
				   .addParam(OAuthConstants.NONCE, NonceUtils.getNonce())
				   .addParam(OAuthConstants.TIMESTAMP, String.valueOf(System.currentTimeMillis() /1000l))
				   .addParam(OAuthConstants.VERSION, getOAuthVersion())
				   .addParam(OAuthConstants.TOKEN, tokenAndUrl.token.getKey())
				   .addParam(OAuthConstants.SIGNATURE_METHOD, getOAuthSignatureMethod().getOAuthName());

		massageAuthorizationRequest(request, webForm, tokenAndUrl, verifier);
		
		// generate the signature for the request
		OAuthUtils.signRequest(request, this.keySecretPair, tokenAndUrl.token, getOAuthSignatureMethod(), webForm);
		
		// sign the request with the details
		switch(getOAuthSignatureType()) {
			
			case HEADER:
				OAuthUtils.buildAuthorizationHeader(request, webForm, getAuthorizationHeaderName(), getAuthorizationHeaderPrefix());
				break;
				
			case QUERY_PARAMS:
				UrlManipulator manipulator = new UrlManipulator(getAuthorizationTokenURL());
				for(NameValuePair pair : webForm.build()) {
					manipulator.setQueryParam(pair.getName(), pair.getValue());
				}
				
				request = WebInvoker.getWebRequest(manipulator.constructURL(), getAuthorizationTokenMethod());
				break;
				
			default:
				throw new AssertionError("Missing case statement for enumeration!");
		}
		
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
			return null;
		}
		
		String content = response.getContent();
		LOGGER.debug("Response content as: {}", content);
		return content;
	}
	
	/**
	 * 
	 * @param request
	 * @param webForm
	 * @param authTokenPair 
	 */
	protected void massageAuthorizationRequest(WebRequest request, WebForm webForm, TokenAndUrl tokenAndUrl, String verifier) {
		// intentionally left blank
	}

	/**
	 * Specify the token extractor to be used after the request token API
	 * has been successfully called. Default is to use the {@link UrlParamTokenExtractor}.
	 * Implementation may override the function if they wish to choose
	 * another {@link TokenExtractor} implementation.
	 * 
	 * @return
	 */
	protected TokenExtractor getRequestTokenExtractor() {
		return new UrlParamTokenExtractor();
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
	 * Return the type of signature that needs to be applied to the request.
	 * 
	 * @return
	 */
	protected OAuthSignatureType getOAuthSignatureType() {
		return OAuthSignatureType.HEADER;
	}

	/**
	 * The version number to be used in the OAuth header. The default value
	 * is {@link OAuthConstants#VERSION_1_0}. Implementations may override
	 * this value in case they need to pass something else.
	 * 
	 * @return
	 */
	protected String getOAuthVersion() {
		return OAuthConstants.VERSION_1_0;
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
	
	/**
	 * @see com.sangupta.jerry.oauth.service.OAuthService#getVerificationCodeParamName()
	 */
	@Override
	public String getVerificationCodeParamName() {
		return "oauth_verifier";
	}
	
}
