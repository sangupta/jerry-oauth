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

import org.apache.http.NameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sangupta.jerry.http.HttpHeaderName;
import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebInvoker;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.http.WebResponse;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.domain.TokenAndUrl;
import com.sangupta.jerry.util.StringUtils;
import com.sangupta.jerry.util.UrlManipulator;

/**
 * Base implementation for all clients that support the OAuth 2.0 specifications.
 * 
 * @author sangupta
 * @since 1.0
 */
public abstract class OAuth2ServiceImpl implements OAuthService {
	
	/**
	 * My logger instance
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth1ServiceImpl.class);
	
	/**
	 * The application specific {@link KeySecretPair} being stored
	 */
	protected final KeySecretPair keySecretPair;
	
	/**
	 * Constructor
	 * 
	 * @param keySecretPair
	 *            the application level key secret pair that needs to be used
	 */
	protected OAuth2ServiceImpl(KeySecretPair keySecretPair) {
		if(keySecretPair == null) {
			throw new IllegalArgumentException("Cannot construct OAuth2 with a null key-secret pair");
		}
		
		this.keySecretPair = keySecretPair;
	}
	
	/**
	 * Return the name of the Access token parameter name
	 * 
	 */
	@Override
	public String getAccessTokenParamName() {
		return OAuthConstants.ACCESS_TOKEN;
	}
	
	/**
	 * Return the name of access token secret parameter name
	 * 
	 */
	@Override
	public String getAccessTokenSecretParamName() {
		return StringUtils.EMPTY_STRING;
	}
	
	/**
	 * Return the name of the refresh token parameter name
	 * 
	 */
	@Override
	public String getRefreshTokenParamName() {
		return OAuthConstants.REFRESH_TOKEN;
	}
	
	/**
	 * Return the name of the access token expiry parameter name
	 * 
	 */
	@Override
	public String getAccessTokenExpiryParamName() {
		return null;
	}
	
	/**
	 * Return the login URL to be used for authenticating a user
	 * 
	 * @return a {@link TokenAndUrl} implementation with the login redirect url
	 */
	@Override
	public TokenAndUrl getLoginURL(String successUrl, String scope) {
		UrlManipulator um = new UrlManipulator(getLoginEndPoint());
		um.setQueryParam(OAuthConstants.SCOPE, scope);
		um.setQueryParam(OAuthConstants.CLIENT_ID, this.keySecretPair.getKey());
		um.setQueryParam("response_type", "code");
		um.setQueryParam(OAuthConstants.REDIRECT_URI, successUrl);

		// massage login to add parameters specific to implementation
		massageLoginURL(um);
		
		// return the constructed url
		return new TokenAndUrl(um.constructURL(), successUrl);
	}
	
	@Override
	public String getAuthorizationResponse(TokenAndUrl tokenAndUrl, String verifier) {
		WebRequest request;
		
		WebForm webForm = WebForm.newForm().addParam("code", verifier)
										   .addParam("client_id", this.keySecretPair.getKey())
										   .addParam("client_secret", this.keySecretPair.getSecret())
										   .addParam("redirect_uri", tokenAndUrl.callbackURL);
		
		massageAuthorizationURL(webForm);

		if(getAuthorizationMethod() == WebRequestMethod.POST) {
			request = WebInvoker.getWebRequest(getAuthorizationEndPoint(), getAuthorizationMethod());
			request.bodyForm(webForm.build());
		} else {
			// this may be a GET request, add parameters to URL
			UrlManipulator manipulator = new UrlManipulator(getAuthorizationEndPoint());
			for(NameValuePair pair : webForm.build()) {
				manipulator.setQueryParam(pair.getName(), pair.getValue());
			}
			
			request = WebInvoker.getWebRequest(manipulator.constructURL(), getAuthorizationMethod());
		}
		
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("Making authorization call to: {}", request.trace());
		}
		
		WebResponse response = WebInvoker.executeSilently(request);
		if(response == null) {
			LOGGER.error("Null response for authorization API call");
			return null;
		}
		
		if(!response.isSuccess()) {
			LOGGER.debug("Unsuccessful call to authorization API: {}", response.trace());
			LOGGER.debug("Response body: {}", response.getContent());
			return null;
		}
		
		String content = response.getContent();
		LOGGER.debug("Authorization response: {}", content);
		return content;
	}

	@Override
	public String signRequestUrl(String url, KeySecretPair userAccessPair) {
		return url;
	}
	
	/**
	 * Sign this request with the provided access pair per the OAuth 2.0 specs.
	 * 
	 * @param request
	 *            the {@link WebRequest} to be signed
	 * 
	 * @param accessPair
	 *            the user-specific key pair to be used
	 */
	@Override
	public void signRequest(WebRequest request, KeySecretPair accessPair) {
		request.addHeader(HttpHeaderName.AUTHORIZATION, "Bearer " + accessPair.getKey());
	}

	protected abstract String getLoginEndPoint();
	
	protected abstract String getAuthorizationEndPoint();
	
	protected String getLoginEndPointRequestType() {
		return "code";
	}
	
	/**
	 * Return the HTTP VERB to be used for authorization of call. The default
	 * value is {@link WebRequestMethod#GET}
	 * 
	 * @return the HTTP VERB to be used
	 */
	protected WebRequestMethod getAuthorizationMethod() {
		return WebRequestMethod.GET;
	}
	
	/**
	 * Massage the login URL for implementation specific properties.
	 * 
	 * @param manipulator
	 *            the {@link UrlManipulator} that is used to create the login
	 *            URL
	 * 
	 */
	protected void massageLoginURL(UrlManipulator manipulator) {
		
	}
	
	/**
	 * Massage the authorization URL for implementation specific properties.
	 * 
	 * @param webForm
	 *            the {@link WebForm} containing all the authorization
	 *            parameters
	 */
	protected void massageAuthorizationURL(WebForm webForm) {
		
	}

	/**
	 * Return the name of the verification parameter that contains the final
	 * verification code
	 * 
	 * @see com.sangupta.jerry.oauth.service.OAuthService#getVerificationCodeParamName()
	 */
	@Override
	public String getVerificationCodeParamName() {
		return "code";
	}
	
}
