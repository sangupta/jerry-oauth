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

package com.sangupta.jerry.oauth.domain;

/**
 * Enumeration different type of signature methods that can be used
 * with OAuth. This also provides a name that can be sent to the OAuth
 * servers, as well as the Java specific algorithm name to be used
 * when signing the request.
 * 
 * @author sangupta
 * @since 1.0
 */
public enum OAuthSignatureMethod {
	
	/**
	 * HMAC-SHA1 
	 */
	HMAC_SHA1("HMAC-SHA1", "HmacSHA1");
	
	/**
	 * The name to be sent to the OAuth server
	 */
	private final String oauthName;
	
	/**
	 * The algorithm name to be used for signing
	 */
	private final String algorithmName;
	
	/**
	 * Constructor
	 * 
	 * @param oauthName the name of the signing method
	 * 
	 * @param algoName the algorithm's Java specific name 
	 */
	private OAuthSignatureMethod(String oauthName, String algoName) {
		this.oauthName = oauthName;
		this.algorithmName = algoName;
	}

	/**
	 * Return the name of the signing method
	 * 
	 * @return
	 */
	public String getOauthName() {
		return oauthName;
	}

	/**
	 * Return the name of the algorithm for this signing method
	 * 
	 * @return
	 */
	public String getAlgorithmName() {
		return algorithmName;
	}

}
