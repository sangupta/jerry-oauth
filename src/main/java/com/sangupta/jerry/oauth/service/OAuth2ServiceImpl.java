package com.sangupta.jerry.oauth.service;

import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebInvoker;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.http.WebResponse;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.util.UrlManipulator;

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
		WebRequest request = WebInvoker.getWebRequest(getAuthorizationEndPoint(), getAuthorizationMethod());
		WebForm webForm = WebForm.newForm().addParam("code", code)
				  .addParam("client_id", this.keySecretPair.getKey())
				  .addParam("client_secret", this.keySecretPair.getSecret())
				  .addParam("redirect_uri", redirectURL);
		massageAuthorizationURL(webForm);
		request.bodyForm(webForm.build());
		
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
