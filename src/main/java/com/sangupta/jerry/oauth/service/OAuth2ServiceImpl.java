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

package com.sangupta.jerry.oauth.service;

import org.apache.http.NameValuePair;

import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebInvoker;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.http.WebResponse;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.util.UrlManipulator;

/**
 * 
 * @author sangupta
 *
 */
public abstract class OAuth2ServiceImpl implements OAuthService {
	
	protected final KeySecretPair keySecretPair;
	
	protected OAuth2ServiceImpl(KeySecretPair keySecretPair) {
		this.keySecretPair = keySecretPair;
	}

	@Override
	public String getLoginURL(String successUrl, String scope) {
		UrlManipulator um = new UrlManipulator(getLoginEndPoint());
		um.setQueryParam(OAuthConstants.OAUTH_SCOPE, scope);
		um.setQueryParam(OAuthConstants.OAUTH_CLIENT_ID, this.keySecretPair.getKey());
		um.setQueryParam("response_type", "code");
		um.setQueryParam(OAuthConstants.OAUTH_REDIRECT_URI, successUrl);

		// massage login to add parameters specific to implementation
		massageLoginURL(um);
		
		// return the constructed url
		return um.constructURL();
	}
	
	public String getAuthorizationResponse(String code, String redirectURL) {
		WebRequest request;
		
		WebForm webForm = WebForm.newForm().addParam("code", code)
				  .addParam("client_id", this.keySecretPair.getKey())
				  .addParam("client_secret", this.keySecretPair.getSecret())
				  .addParam("redirect_uri", redirectURL);
		massageAuthorizationURL(webForm);

		if(getAuthorizationMethod() == WebRequestMethod.POST) {
			request = WebInvoker.getWebRequest(getAuthorizationEndPoint(), getAuthorizationMethod());
			request.bodyForm(webForm.build());
		} else {
			// this may be a GET request, add parameters to URL
			UrlManipulator manipulator = new UrlManipulator(getAuthorizationEndPoint());
			for(NameValuePair pair : webForm.build()) {
				manipulator.setQueryParam(pair.getName(), pair.getValue());
			}
			
			request = WebInvoker.getWebRequest(manipulator.constructURL(), getAuthorizationMethod());
		}
		
		WebResponse response = WebInvoker.executeSilently(request);
		if(response == null || !response.isSuccess()) {
			System.out.println("null or error response");
			System.out.println(response.trace());
			System.out.println(response.getContent());
			return null;
		}
		
		return response.getContent();
	}

	protected abstract String getLoginEndPoint();
	
	protected abstract String getAuthorizationEndPoint();
	
	protected abstract WebRequestMethod getAuthorizationMethod();
	
	protected abstract void massageLoginURL(UrlManipulator manipulator);
	
	protected abstract void massageAuthorizationURL(WebForm webForm);

}
