/**
 *
 * jerry - Common Java Functionality
 * Copyright (c) 2012, Sandeep Gupta
 * 
 * http://www.sangupta/projects/jerry
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

import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.oauth.domain.KeySecretPair;

/**
 * 
 * @author sangupta
 *
 */
public interface OAuthService {
	
	/**
	 * Get the authentication URL that the user needs to be redirected to.
	 * 
	 * @param successUrl the callback success url that the call will come back to
	 * 
	 * @param scope the scopes to be used for authentication
	 * 
	 */
	public String getLoginURL(String successUrl, String scope);
	
	/**
	 * 
	 * @param request
	 * @param accessPair
	 */
	public void signRequest(WebRequest request, KeySecretPair accessPair);
	
}
