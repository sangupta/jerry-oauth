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
