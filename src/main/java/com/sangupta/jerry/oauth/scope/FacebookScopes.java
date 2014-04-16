/**
 *
 * jerry-oauth : Common Java OAuth functionality
 * Copyright (c) 2012-2014, Sandeep Gupta
 * 
 * http://sangupta.com/projects/jerry-oauth
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

package com.sangupta.jerry.oauth.scope;

/**
 * Facebook permissions allowed per the URL
 * https://developers.facebook.com/docs/facebook-login/permissions
 * 
 * @author sangupta
 * @since 1.0
 */
public interface FacebookScopes {
	
	// basic scopes
	
	public static final String BASIC_INFO = "basic_info";
	
	public static final String EMAIL = "email";
	
	// extended profile scopes
	
	public static final String USER_ABOUT_ME = "user_about_me";
	
	public static final String FRIENDS_ABOUT_ME = "friends_about_me";
	
	public static final String USER_ACTIVITIES = "user_activities";
	
	public static final String FRIENDS_ACTIVITIES = "friends_activities";
	
	public static final String USER_BIRTHDAY = "user_birthday";
	
	public static final String FRIENDS_BIRTHDAY = "friends_birthday";
	
	public static final String USER_CHECKINS = "user_checkins";
	
	public static final String FRIENDS_CHECKINS = "friends_checkins";
	
	public static final String USER_EDUCATION_HISTORY = "user_education_history";
	
	public static final String FRIENDS_EDUCATION_HISTORY = "friends_education_history";
	
	public static final String USER_EVENTS = "user_events";
	
	public static final String FRIENDS_EVENTS = "friends_events";
	
	public static final String USER_GROUPS = "user_groups";
	
	public static final String FRIENDS_GROUPS = "friends_groups";
	
	public static final String USER_HOMETOWN = "user_hometown";
	
	public static final String FRIENDS_HOMETOWN = "friends_hometown";
	
	public static final String USER_INTERESTS = "user_interests";
	
	public static final String FRIENDS_INTERESTS = "friends_interests";
	
	public static final String USER_LIKES = "user_likes";
	
	public static final String FRIENDS_LIKES = "friends_likes";
	
	public static final String USER_LOCATION = "user_location";
	
	public static final String FRIENDS_LOCATION = "friends_location";
	
	public static final String USER_NOTES = "user_notes";
	
	public static final String FRIENDS_NOTES = "friends_notes";
	
	public static final String USER_PHOTOS = "user_photos";
	
	public static final String FRIENDS_PHOTOS = "friends_photos";
	
	public static final String USER_QUESTIONS = "user_questions";
	
	public static final String FRIENDS_QUESTIONS = "friends_questions";
	
	public static final String USER_RELATIONSHIPS = "user_relationships";
	
	public static final String FRIENDS_RELATIONSHIPS = "friends_relationships";
	
	public static final String USER_RELATIONSHIP_DETAILS = "user_relationship_details";
	
	public static final String FRIENDS_RELATIONSHIP_DETAILS = "friends_relationship_details";
	
	public static final String USER_RELIGION_POLITICS = "user_religion_politics";
	
	public static final String FRIENDS_RELIGION_POLITICS = "friends_religion_politics";
	
	public static final String USER_STATUS = "user_status";
	
	public static final String FRIENDS_STATUS = "friends_status";
	
	public static final String USER_SUBSCRIPTIONS = "user_subscriptions";
	
	public static final String FRIENDS_SUBSCRIPTIONS = "friends_subscriptions";
	
	public static final String USER_VIDEOS = "user_videos";
	
	public static final String FRIENDS_VIDEOS = "friends_videos";
	
	public static final String USER_WEBSITE = "user_website";
	
	public static final String FRIENDS_WEBSITE = "friends_website";
	
	public static final String USER_WORK_HISTORY = "user_work_history";
	
	public static final String FRIENDS_WORK_HISTORY = "friends_work_history";
	
	// extended permissions - read
	
	public static final String READ_FRIENDS_LIST = "read_friendlists";
	
	public static final String READ_INSIGHTS = "read_insights";
	
	public static final String READ_MAILBOX = "read_mailbox";
	
	public static final String READ_REQUESTS = "read_requests"; 
	
	public static final String READ_STREAM = "read_stream";
	
	public static final String XMPP_LOGIN = "xmpp_login";
	
	public static final String USER_ONLINE_PRESENCE = "user_online_presence";
	
	public static final String FRIENDS_ONLINE_PRESENCE = "friends_online_presence";
	
	// extended permissions - publish
	
	public static final String ADS_MANAGEMENT = "ads_management";
	
	public static final String CREATE_EVENT = "create_event";
	
	public static final String MANAGE_FRIENDLISTS = "manage_friendlists";
	
	public static final String MANAGE_NOTIFICATIONS = "manage_notifications";
	
	public static final String PUBLISH_ACTIONS = "publish_actions";
	
	public static final String PUBLISH_STREAM = "publish_stream";
	
	public static final String RSVP_EVENT = "rsvp_event";
	
	// open graph permissions
	
	public static final String USER_ACTIONS_MUSIC = "user_actions.music";
	
	public static final String FRIENDS_ACTIONS_MUSIC = "friends_actions.music";
	
	public static final String USER_ACTIONS_NEWS = "user_actions.news";
	
	public static final String FRIENDS_ACTIONS_NEWS = "friends_actions.news";
	
	public static final String USER_ACTIONS_VIDEO = "user_actions.video";
	
	public static final String FRIENDS_ACTIONS_VIDEO = "friends_actions.video";
	
	public static final String USER_GAMES_ACTIVITY = "user_games_activity";
	
	public static final String FRIENDS_GAMES_ACTIVITY = "friends_games_activity";
	
	// pages
	
	public static final String MANAGE_PAGES = "manage_pages";
	
	public static final String READ_PAGE_MAILBOXES = "read_page_mailboxes";
	
}
