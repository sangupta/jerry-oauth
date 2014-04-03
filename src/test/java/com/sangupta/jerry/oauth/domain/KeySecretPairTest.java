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

package com.sangupta.jerry.oauth.domain;

import junit.framework.Assert;

import org.junit.Test;

/**
 * 
 * @author sangupta
 *
 */
public class KeySecretPairTest {

	@Test
	public void testKeySecretPair() {
		KeySecretPair pair = new KeySecretPair(null, null);
		Assert.assertNull(pair.getKey());
		Assert.assertNull(pair.getSecret());
		
		pair = new KeySecretPair("12", "23");
		Assert.assertNotNull(pair.getKey());
		Assert.assertEquals("12", pair.getKey());
		Assert.assertNotNull(pair.getSecret());
		Assert.assertEquals("23", pair.getSecret());
		
		KeySecretPair samePair = new KeySecretPair("12", "23");
		Assert.assertEquals(pair.hashCode(), samePair.hashCode());
		Assert.assertEquals(pair, samePair);

		KeySecretPair diffPair = KeySecretPair.uuidRandomToken();
		Assert.assertFalse(pair.equals(diffPair));
	}
}
