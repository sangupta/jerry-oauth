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

import java.util.HashMap;
import java.util.Map;

import com.sangupta.jerry.util.AssertUtils;

/**
 * A {@link TokenExtractor} implementation that takes in URL-encoded
 * parameter string and parses to extract token parameters.
 * 
 * @author sangupta
 * @since 1.0
 */
public class UrlParamExtractor implements TokenExtractor {

	@Override
	public Map<String, String> extractTokens(String webResponse) {
		if(AssertUtils.isEmpty(webResponse)) {
			return TokenExtractor.EMPTY_TOKEN_MAP;
		}
		
		Map<String, String> map = new HashMap<String, String>();
		String[] tokens = webResponse.split("&");
		for(String token : tokens) {
			String[] pair = token.split("=");
			if(pair.length == 2) {
				map.put(pair[0], pair[1]);
			}
		}
		
		return map;
	}

}
