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
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.TokenAndUrl;

/**
 * Base contract for all OAuth based services: 1.0, 2.0 or hybrid. Decouples
 * the callee from the actual implementation to be used.
 * 
 * @author sangupta
 * @since 1.0
 */
public interface OAuthService {
	
	/**
	 * Get the authentication URL that the user needs to be redirected to.
	 * 
	 * @param successUrl
	 *            the callback success url that the call will come back to
	 * 
	 * @param scope
	 *            the scopes to be used for authentication
	 * 
	 * @return the login url to which the user should be redirected
	 * 
	 */
	public TokenAndUrl getLoginURL(String successUrl, String scope);
	
	/**
	 * Return the authorization response for the given tokenCode and verifier as presented. The
	 * tokenCode and verifier are provided by the authentication provider either in the redirected
	 * request, or as a user-key-able token on the screen (used in desktop scenarios).
	 * 
	 * @param tokenCode
	 * @param verifier
	 * @param redirectURL
	 * @return
	 */
	public String getAuthorizationResponse(TokenAndUrl tokenAndUrl, String verifier);
	
	/**
	 * Sign the given request URL using the given user access pair. This is
	 * useful where access token needs to be passed as a request parameter, than
	 * request headers. Some stupid folks like at Microsoft do it - rather than
	 * accepting a {@link HttpHeaderName#AUTHORIZATION} header.
	 * 
	 * @param url
	 * @param userAccessPair
	 * @return
	 */
	public String signRequestUrl(String url, KeySecretPair userAccessPair);
	
	/**
	 * Sign the given request using the given access pair. The access pair
	 * provided here is the user specific key-pair. The application-specific key
	 * pair must already have been provided when constructing an implementation
	 * of the OAuth service.
	 * 
	 * @param request
	 *            the {@link WebRequest} that needs to be signed
	 * 
	 * @param userAccessPair
	 *            the user specific key-pair to be used for signing. This can be
	 *            <code>null</code> if the request has no user-specific token to
	 *            be applied.
	 */
	public void signRequest(WebRequest request, KeySecretPair userAccessPair);
	
}
