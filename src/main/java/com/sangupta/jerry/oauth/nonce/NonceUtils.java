package com.sangupta.jerry.oauth.nonce;

import java.util.UUID;

/**
 * Some utility functions around NONCE strings
 * used in OAuth world.
 * 
 * @author sangupta
 * @since 1.0
 */
public class NonceUtils {
	
	/**
	 * Return a UUID based nonce token that can be used
	 * when sending to OAuth servers.
	 * 
	 * @return
	 */
	public static String getUUIDNonce() {
		return UUID.randomUUID().toString();
	}

}
