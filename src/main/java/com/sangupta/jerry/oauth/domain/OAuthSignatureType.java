package com.sangupta.jerry.oauth.domain;

/**
 * 
 * @author sangupta
 *
 */
public enum OAuthSignatureType {
	
	/**
	 * Include signature params in authorization header
	 */
	HEADER,
	
	/**
	 * Include params in request as query params
	 */
	QUERY_PARAMS;

}
