package com.sangupta.jerry.oauth.service.impl;

import com.sangupta.jerry.oauth.domain.KeySecretPair;
import com.sangupta.jerry.oauth.service.OAuth2ServiceImpl;
import com.sangupta.jerry.util.AssertUtils;
import com.sangupta.jerry.util.UrlManipulator;

public class GoogleOAuthServiceImpl extends OAuth2ServiceImpl {
	
	private String loginHint = null;
	
	public GoogleOAuthServiceImpl(KeySecretPair keySecretPair) {
		super(keySecretPair);
	}

	public static final String END_POINT = "https://accounts.google.com/o/oauth2/auth";
	
	@Override
	protected void massageLoginURL(UrlManipulator um) {
		um.setQueryParam("access_type", "online");
		um.setQueryParam("approval_prompt", "auto");
		
		if(AssertUtils.isNotBlank(this.loginHint)) {
			um.setQueryParam("login_hint", this.loginHint);
		}
		um.setQueryParam("include_granted_scopes", "false");
	}

	@Override
	protected String getLoginEndPoint() {
		return END_POINT;
	}

	public void setLoginHint(String loginHint) {
		this.loginHint = loginHint;
	}
}
