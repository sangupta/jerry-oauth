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

package com.sangupta.jerry.oauth.extractor;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Contract for implementations that need to parse various formats of tokens
 * presented. Implementations must make sure that they are thread safe.
 * 
 * @author sangupta
 * @since 1.0
 */
public interface TokenExtractor {
	
	/**
	 * An unmodifiable map that is always empty. Adding keys to the map will
	 * result in an {@link UnsupportedOperationException}.
	 */
	public static final Map<String, String> EMPTY_TOKEN_MAP = Collections.unmodifiableMap(new HashMap<String, String>());
	
	/**
	 * Extract the tokens from the given response and return them as a
	 * {@link Map}.
	 * 
	 * @param webResponse
	 * @return
	 */
	public Map<String, String> extractTokens(String webResponse);

}
