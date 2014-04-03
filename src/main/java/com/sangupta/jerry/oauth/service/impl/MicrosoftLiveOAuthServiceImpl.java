package com.sangupta.jerry.oauth.service.impl;

import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;

/**
 * OAuth implementation for http://live.com
 * 
 * @author sangupta
 * @since 1.0
 */
public class MicrosoftLiveOAuthServiceImpl extends OAuth2ServiceImpl {

	public MicrosoftLiveOAuthServiceImpl(KeySecretPair keySecretPair) {
		super(keySecretPair);
	}
	
	@Override
	protected String getLoginEndPointRequestType() {
		return "code";
	}

	@Override
	protected String getLoginEndPoint() {
		return "https://login.live.com/oauth20_authorize.srf";
	}
	
	@Override
	protected WebRequestMethod getAuthorizationMethod() {
		return WebRequestMethod.POST;
	}

	@Override
	protected String getAuthorizationEndPoint() {
		return "https://login.live.com/oauth20_token.srf";
	}
	
	@Override
	protected void massageAuthorizationURL(WebForm webForm) {
		webForm.addParam("grant_type", "authorization_code");
	}

}
