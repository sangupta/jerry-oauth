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

package com.sangupta.jerry.oauth.scope;

/**
 * Linkedin scopes from https://developer.linkedin.com/documents/authentication#granting
 * 
 * @author sangupta
 * @since 1.0
 */
public interface LinkedInScopes {
	
	public static final String BASIC_PROFILE = "r_basicprofile";
	
	public static final String FULL_PROFILE = "r_fullprofile";
	
	public static final String EMAIL = "r_emailaddress";
	
	public static final String NETWORK = "r_network";
	
	public static final String CONTACT_INFO = "r_contactinfo";
	
	public static final String NETWORK_UPDATES = "rw_nus";
	
	public static final String COMPANY_PAGE_ADMIN = "rw_company_admin";
	
	public static final String GROUPS = "rw_groups";
	
	public static final String MESSAGES = "w_messages";
	
}
