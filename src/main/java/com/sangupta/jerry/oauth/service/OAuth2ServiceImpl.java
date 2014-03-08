package com.sangupta.jerry.oauth.service;

import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.util.UrlManipulator;

public abstract class OAuth2ServiceImpl implements OAuthService {
	
	protected String scope;
	
	protected final KeySecretPair keySecretPair;
	
	protected OAuth2ServiceImpl(KeySecretPair keySecretPair) {
		this.keySecretPair = keySecretPair;
	}

	@Override
	public String getLoginURL(String successUrl) {
		UrlManipulator um = new UrlManipulator(getLoginEndPoint());
		um.setQueryParam(OAuthConstants.OAUTH_SCOPE, this.scope);
		um.setQueryParam(OAuthConstants.OAUTH_CLIENT_ID, this.keySecretPair.getKey());
		um.setQueryParam("response_type", "code");
		um.setQueryParam(OAuthConstants.OAUTH_REDIRECT_URI, successUrl);
		
		massageLoginURL(um);
		
		return um.constructURL();
	}
	
	@Override
	public void setScope(String scope) {
		this.scope = scope;
	}

	protected abstract String getLoginEndPoint();
	
	protected abstract void massageLoginURL(UrlManipulator manipulator);

}
