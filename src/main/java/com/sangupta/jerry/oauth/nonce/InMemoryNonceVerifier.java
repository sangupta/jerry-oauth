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

import java.util.Iterator;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeSet;

import com.sangupta.jerry.util.DateUtils;

/**
 * A simple in-memory implementation of {@link NonceVerifier} that compares all token
 * globally and NOT per consumer key.
 * 
 * @author sangupta
 * @since 1.0
 */
public class InMemoryNonceVerifier implements NonceVerifier {
	
	/**
	 * Holds list of all current tokens
	 */
	private final Set<NonceToken> tokens = new TreeSet<NonceToken>();
	
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
	 * Default Constructor - will clean up all old tokens that are more than 
	 * one day old, and the cleaning up frequency is one hour.
	 * 
	 */
	public InMemoryNonceVerifier() {
		this(DateUtils.ONE_DAY, DateUtils.ONE_HOUR);
	}
	
	/**
	 * Construct an verifier with the given expiration time of tokens, and the given
	 * clean up frequency.
	 * 
	 * @param expirationTime
	 * @param cleanUpFrequency
	 */
	public InMemoryNonceVerifier(long expirationTime, long cleanUpFrequency) {
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
	 * Verify if the nonce has previously been used or not.
	 * 
	 * @see com.sangupta.jerry.oauth.nonce.NonceVerifier#verifyNonce(java.lang.String, java.lang.String)
	 */
	@Override
	public boolean verifyNonce(String consumerKey, String nonce) {
		NonceToken token = new NonceToken(nonce);
        if(tokens.contains(token)) {
            return false;
        }
        
        return tokens.add(token);
	}
	
	/**
     * Clean up tokens older than the expiration time.
     */
    private void cleanUpOldTokens() {
        if(this.tokens.isEmpty()) {
            // nothing to do - return
        }
        
        final long currentRunningTime = System.currentTimeMillis();
        
        Iterator<NonceToken> iterator = tokens.iterator();
        while(iterator.hasNext()) {
            NonceToken token = iterator.next();
            
            long delta = currentRunningTime - token.millis;
            if(this.EXPIRATION_TIME < delta) {
                iterator.remove();
            }
        }
    }

	/**
	 * Class that holds a single Nonce value and a timestamp as to when was it
	 * submitted. The values are removed after a certain timeperiod.
	 * 
	 * @author sangupta
	 *
	 */
	private static class NonceToken implements Comparable<NonceToken> {
		
		String nonce;
		
		long millis;
		
		public NonceToken(String nonce) {
			this.nonce = nonce;
			this.millis = System.currentTimeMillis();
		}
		
		public int compareTo(NonceToken other) {
			if(other == null) {
				return -1;
			}
			
			if(millis < other.millis) {
				return -1;
			}
			
			if(millis == other.millis) {
				return 0;
			}
			
			return 1;
		}
		
		/**
		 * @see java.lang.Object#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(Object obj) {
			if(obj == null) {
                return false;
            }
            
            if(this == obj) {
                return true;
            }
            
            if(!(obj instanceof NonceToken)) {
                return false;
            }
            
            NonceToken other = (NonceToken) obj;
            return this.nonce.equals(other.nonce);
        }

        @Override
        public int hashCode() {
            return this.nonce.hashCode();
        }
	}
}
