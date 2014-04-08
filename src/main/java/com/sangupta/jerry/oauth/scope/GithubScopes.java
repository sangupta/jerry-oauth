package com.sangupta.jerry.oauth.scope;

/**
 * Github scopes as defined at https://developer.github.com/v3/oauth/#scopes
 * 
 * @author sangupta
 *
 */
public interface GithubScopes {
	
	public static final String PUBLIC_INFO = "";
	
	public static final String USER = "user";
	
	public static final String EMAIL = "user:email";
	
	public static final String FOLLOW = "user:follow";
	
	public static final String PUBLIC_REPO = "repo";
	
	public static final String REPO_DEPLOYMENT = "repo_deployment";
	
	public static final String REPO_STATUS = "repo:status";
	
	public static final String REPO_DELETE = "delete_repo";
	
	public static final String NOTIFICATIONS = "notifications";
	
	public static final String GIST = "gist";
	
	public static final String READ_REPO_HOOK = "read:repo_hook";
	
	public static final String WRITE_REPO_HOOK = "write:repo_hook";
	
	public static final String ADMIN_REPO_HOOK = "admin:repo_hook";
	
	public static final String READ_ORG = "read:org";
	
	public static final String WRITE_ORG = "write:org";
	
	public static final String ADMIN_ORG = "admin:org";
	
	public static final String READ_PUBLIC_KEY = "read:public_key";
	
	public static final String WRITE_PUBLIC_KEY = "write:public_key";
	
	public static final String ADMIN_PUBLIC_KEY = "admin:public_key";

}
