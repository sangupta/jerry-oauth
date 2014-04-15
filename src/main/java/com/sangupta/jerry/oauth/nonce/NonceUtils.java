package com.sangupta.jerry.oauth.nonce;

import java.util.UUID;

import com.sangupta.jerry.encoder.Base62Encoder;

/**
 * Some utility functions around NONCE strings
 * used in OAuth world.
 * 
 * @author sangupta
 * @since 1.0
 */
public class NonceUtils {
	
	/**
	 * Return a UUID based nonce token that can be used when sending to OAuth
	 * servers.
	 * 
	 * @return a {@link UUID} based nonce
	 */
	public static String getUUIDNonce() {
		return UUID.randomUUID().toString();
	}

	/**
	 * Generates an encoded nonce that comprises of a UUID, the current system
	 * time, and the time in nanoseconds.
	 * 
	 * @return a {@link UUID}, timestamp and nanotime based nonce that is base62
	 *         encoded
	 */
	public static String getNonce() {
		UUID uuid = UUID.randomUUID();
		return Base62Encoder.encode(uuid.getMostSignificantBits(), uuid.getLeastSignificantBits(), System.currentTimeMillis(), System.nanoTime());
	}
}
