package com.sangupta.jerry.oauth.service;

public interface OAuthService {
	
	public String getLoginURL(String successUrl);
	
	public void setScope(String scope);

}
