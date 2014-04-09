package com.sangupta.jerry.oauth.service.impl;

import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;
import com.sangupta.jerry.util.UrlManipulator;

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
		webForm.addParam(OAuthConstants.GRANT_TYPE, OAuthConstants.GRANT_AUTHORIZATION_CODE);
	}

	@Override
	public String signRequestUrl(String url, KeySecretPair userAccessPair) {
		UrlManipulator manipulator = new UrlManipulator(url);
		manipulator.setQueryParam(OAuthConstants.ACCESS_TOKEN, userAccessPair.getKey());
		return manipulator.constructURL();
	}
	
	@Override
	public void signRequest(WebRequest request, KeySecretPair accessPair) {
		// do nothing
	}
}
