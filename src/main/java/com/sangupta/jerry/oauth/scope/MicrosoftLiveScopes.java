package com.sangupta.jerry.oauth.scope;

/**
 * Read more on Microsoft Live scopes here: http://msdn.microsoft.com/en-us/library/live/hh243646.aspx
 * 
 * @author sangupta
 *
 */
public interface MicrosoftLiveScopes {
	
	public static final String READ_USER_PROFILE = "wl.basic";
	
	public static final String OFFLINE_ACCESS = "wl.offline_access";
	
	public static final String SINGLE_SIGN_IN = "wl.signin";

}
