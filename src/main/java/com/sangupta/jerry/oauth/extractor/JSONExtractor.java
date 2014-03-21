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

package com.sangupta.jerry.oauth.extractor;

import java.util.Map;

import com.sangupta.jerry.util.GsonUtils;

/**
 * Parses the the JSON input and returns a {@link Map} with keys as the
 * field name and the values, as field values.
 *  
 * @author sangupta
 * @since 1.0
 */
public class JSONExtractor implements TokenExtractor {

	@Override
	public Map<String, String> extractTokens(String webResponse) {
		@SuppressWarnings("unchecked")
		Map<String, String> map = GsonUtils.getGson().fromJson(webResponse, Map.class);
		
		return map;
	}

}
