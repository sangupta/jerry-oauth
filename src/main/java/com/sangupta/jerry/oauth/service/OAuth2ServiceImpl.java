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
import com.sangupta.jerry.util.UrlManipulator;

/**
 * Base implementation for all clients that support the OAuth 2.0 specifications.
 * 
 * @author sangupta
 * @since 1.0
 */
public abstract class OAuth2ServiceImpl implements OAuthService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth1ServiceImpl.class);
	
	protected final KeySecretPair keySecretPair;
	
	protected OAuth2ServiceImpl(KeySecretPair keySecretPair) {
		this.keySecretPair = keySecretPair;
	}
	
	@Override
	public String getLoginURL(String successUrl, String scope) {
		UrlManipulator um = new UrlManipulator(getLoginEndPoint());
		um.setQueryParam(OAuthConstants.OAUTH_SCOPE, scope);
		um.setQueryParam(OAuthConstants.OAUTH_CLIENT_ID, this.keySecretPair.getKey());
		um.setQueryParam("response_type", "code");
		um.setQueryParam(OAuthConstants.OAUTH_REDIRECT_URI, successUrl);

		// massage login to add parameters specific to implementation
		massageLoginURL(um);
		
		// return the constructed url
		return um.constructURL();
	}
	
	@Override
	public String getAuthorizationResponse(String tokenCode, String verifier, String redirectURL) {
		WebRequest request;
		
		WebForm webForm = WebForm.newForm().addParam("code", tokenCode)
										   .addParam("client_id", this.keySecretPair.getKey())
										   .addParam("client_secret", this.keySecretPair.getSecret())
										   .addParam("redirect_uri", redirectURL);
		
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
		
		return response.getContent();
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
	 * 
	 * @return
	 */
	protected WebRequestMethod getAuthorizationMethod() {
		return WebRequestMethod.GET;
	}
	
	/**
	 * Massage the login URL for implementation specific properties.
	 * 
	 * @param manipulator
	 */
	protected void massageLoginURL(UrlManipulator manipulator) {
		
	}
	
	/**
	 * Massage the authorization URL for implementation specific properties.
	 * 
	 * @param webForm
	 */
	protected void massageAuthorizationURL(WebForm webForm) {
		
	}

}
