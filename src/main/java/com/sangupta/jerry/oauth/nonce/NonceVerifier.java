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

package com.sangupta.jerry.oauth.nonce;

/**
 * A contract for any service that wants to work as a <b>Nonce</b>
 * verifying service for OAuth based requests.
 * 
 * @author sangupta
 * @since 1.0
 */
public interface NonceVerifier {

	/**
	 * Check if this nonce has been used against the given consumer key.
	 * Implementations may choose to ignore the consumer key and verify
	 * nonce on a global level.
	 * 
	 * @param consumerKey
	 * @param nonce
	 * @return
	 */
	public boolean verifyNonce(String consumerKey, String nonce);
	
}
