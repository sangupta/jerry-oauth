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

package com.sangupta.jerry.oauth.token;

import java.util.Collection;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.util.AssertUtils;
import com.sangupta.jerry.util.DateUtils;

/**
 * An in-memory {@link OAuthTokenGenerator} that can be used to generate
 * OAuth request/access tokens for sending to the client.
 * 
 * @author sangupta
 *
 */
public class InMemoryOAuthTokenGenerator implements OAuthTokenGenerator {
	
	/**
     * Holds all tokens
     */
    private final ConcurrentMap<String, OAuthTokenWrapper> TOKEN_TO_KEY_MAP = new ConcurrentHashMap<String, OAuthTokenWrapper>();
	
	/**
	 * The background cleaning task
	 */
	private final TimerTask timerTask;
	
	/**
	 * The background cleaning time
	 */
	private final Timer timer;
	
	/**
	 * Time duration after which the token is considered expired
	 */
	private final long EXPIRATION_TIME;
	
	/**
	 * Default constructor that creates a generator that provides a token with
	 * one day validity and older tokens are removed every hour.
	 * 
	 */
	public InMemoryOAuthTokenGenerator() {
		this(DateUtils.ONE_DAY, DateUtils.ONE_HOUR);
	}
	
	/**
	 * Create a new generator that provides a token with the given expiration time and
	 * removes older tokens at the given frequency.
	 * 
	 * @param expirationTime
	 * @param cleanUpFrequency
	 */
	public InMemoryOAuthTokenGenerator(long expirationTime, long cleanUpFrequency) {
		this.EXPIRATION_TIME = expirationTime;
		
		this.timerTask = new TimerTask() {

            @Override
            public void run() {
                cleanUpOldTokens();
            }

        };
        
        // start timer
        this.timer = new Timer("nonce-cleaning-task");
        this.timer.scheduleAtFixedRate(timerTask, DateUtils.FIVE_MINUTES, cleanUpFrequency);
	}

	/**
	 * @see com.sangupta.jerry.oauth.token.OAuthTokenGenerator#generateKeyPair(java.lang.String)
	 */
	@Override
	public KeySecretPair generateKeyPair(String consumerKey) {
		if(AssertUtils.isEmpty(consumerKey)) {
			throw new IllegalArgumentException("Consumer key cannot be null/empty");
		}
		
		do {
			KeySecretPair token = KeySecretPair.uuidRandomToken();
			OAuthTokenWrapper olderToken = TOKEN_TO_KEY_MAP.putIfAbsent(token.getKey(), new OAuthTokenWrapper(token, consumerKey));
			if(olderToken == null) {
				return token;
			}
			
		} while(true);
	}

	/**
	 * @see com.sangupta.jerry.oauth.token.OAuthTokenGenerator#getSecret(java.lang.String, java.lang.String)
	 */
	@Override
	public String getSecret(String consumerKey, String requestToken) {
		if(AssertUtils.isEmpty(consumerKey)) {
			return null;
		}
		
		if(AssertUtils.isEmpty(requestToken)) {
			return null;
		}
		
		if(!TOKEN_TO_KEY_MAP.containsKey(requestToken)) {
            return null;
        }
        
        OAuthTokenWrapper wrapper = TOKEN_TO_KEY_MAP.get(requestToken);
        if(!wrapper.consumerKey.equals(consumerKey)) {
            return null;
        }
        
        // check for expiration
        long currentTime = System.currentTimeMillis();
        long delta = currentTime - wrapper.millis;
        if(delta > this.EXPIRATION_TIME) {
        	// remove the expired token
        	TOKEN_TO_KEY_MAP.remove(requestToken);
        	
            return null;
        }
        
        return wrapper.token.getSecret();
	}
	
	/**
     * Clean up tokens older than the expiration time.
     */
    private void cleanUpOldTokens() {
    	if(TOKEN_TO_KEY_MAP.isEmpty()) {
            // nothing to do - return
        }
        
        final long currentRunningTime = System.currentTimeMillis();
        
        Collection<OAuthTokenWrapper> values = TOKEN_TO_KEY_MAP.values();
        
        for(OAuthTokenWrapper tokenWrapper : values) {
        	long delta = currentRunningTime - tokenWrapper.millis;
            if(this.EXPIRATION_TIME < delta) {
                TOKEN_TO_KEY_MAP.remove(tokenWrapper.token);
            }
        }
    }

    /**
     * Utility class that binds a given token to a given consumer key.     * 
     * 
     * @author sangupta
     *
     */
	private static class OAuthTokenWrapper {
		
		KeySecretPair token;
		
		String consumerKey;
		
		long millis;
		
		public OAuthTokenWrapper(KeySecretPair token, String consumerKey) {
			this.token = token;
			this.consumerKey = consumerKey;
			this.millis = System.currentTimeMillis();
		}
	}
}
