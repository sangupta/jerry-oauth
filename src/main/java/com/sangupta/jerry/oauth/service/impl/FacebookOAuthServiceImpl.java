package com.sangupta.jerry.oauth.service.impl;

import com.sangupta.jerry.http.HttpHeaderName;
import com.sangupta.jerry.http.WebForm;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;
import com.sangupta.jerry.util.UrlManipulator;

public class FacebookOAuthServiceImpl extends OAuth2ServiceImpl {

public static final String END_POINT = "https://www.facebook.com/dialog/oauth";
	
	public static final String AUTH_END_POINT = "https://graph.facebook.com/oauth/access_token";
	
	public FacebookOAuthServiceImpl(KeySecretPair keySecretPair) {
		super(keySecretPair);
	}

	@Override
	protected void massageLoginURL(UrlManipulator um) {
	}

	@Override
	protected String getLoginEndPoint() {
		return END_POINT;
	}

	@Override
	protected String getAuthorizationEndPoint() {
		return AUTH_END_POINT;
	}

	@Override
	protected WebRequestMethod getAuthorizationMethod() {
		return WebRequestMethod.GET;
	}

	@Override
	public void signRequest(WebRequest request, KeySecretPair accessPair) {
		request.addHeader(HttpHeaderName.AUTHORIZATION, "Bearer " + accessPair.getKey());
	}

	@Override
	protected void massageAuthorizationURL(WebForm webForm) {
		// do nothing
	}

}
