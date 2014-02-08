/**
 *
 * jerry - Common Java Functionality
 * Copyright (c) 2012, Sandeep Gupta
 * 
 * http://www.sangupta/projects/jerry
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

package com.sangupta.jerry.oauth;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import com.sangupta.jerry.encoder.Base62Encoder;
import com.sangupta.jerry.encoder.Base64Encoder;
import com.sangupta.jerry.http.WebInvoker;
import com.sangupta.jerry.http.WebRequest;
import com.sangupta.jerry.http.WebRequestMethod;
import com.sangupta.jerry.oauth.domain.OAuthConstants;
import com.sangupta.jerry.oauth.domain.OAuthSignatureMethod;
import com.sangupta.jerry.oauth.domain.OAuthToken;
import com.sangupta.jerry.util.AssertUtils;
import com.sangupta.jerry.util.StringUtils;
import com.sangupta.jerry.util.UriUtils;

/**
 * Utility methods to work with OAuth based requests.
 * 
 * @author sangupta
 *
 */
public class OAuthUtils {
	
	public static WebRequest signRequest(WebRequest request, OAuthToken consumer, OAuthToken userToken, String timeStamp, String nonce) {
		StringBuilder builder = new StringBuilder();
		
		// first the HTTP VERB
		builder.append(request.getVerb().toString().toUpperCase());
		builder.append("&");
		
		// then the end point without any path or query or fragment
		URI uri = request.getURI();
		builder.append(getSignableBase(uri));
		
		// collect all parameters
		TreeMap<String, String> requestParams = extractURIParameters(uri);
		String paramString = buildParamString(null, requestParams);
		
		// now build up the signing string
		final String signable = builder.toString();
		
		// compute the signature
		final String signature = generateSignature(consumer, userToken, signable, OAuthSignatureMethod.HMAC_SHA1);
		
		// append to the request
//		params.put(OAuthConstants.OAUTH_SIGNATURE, signature);
//		
//		// build oauth header
//		request.addHeader(HttpHeaderName.AUTHORIZATION, "OAuth " + getAllOAuthParams(params));
		
		return request;
	}
	
	public static String buildParamString(Object object, TreeMap<String, String> params) {
		StringBuilder builder = new StringBuilder();
		
//		params.put(OAuthConstants.OAUTH_CONSUMER_KEY, consumerKey);
//		params.put(OAuthConstants.OAUTH_NONCE, generateNonce());
//		params.put(OAuthConstants.OAUTH_SIGNATURE_METHOD, signatureMethod.getOauthName());
//		params.put(OAuthConstants.OAUTH_TIMESTAMP, String.valueOf(System.currentTimeMillis()));
//		params.put(OAuthConstants.OAUTH_VERSION, oAuthVersion);
		
		return builder.toString();
	}
	
	/**
	 * Extract all the query parameters from the URI
	 * 
	 * @param uri
	 * @return
	 */
	public static TreeMap<String, String> extractURIParameters(URI uri) {
		String query = uri.getQuery();
		if(AssertUtils.isEmpty(query)) {
			return null;
		}
		
		TreeMap<String, String> params = new TreeMap<String, String>();
		String[] pairs = query.split("&");
		for(String pair : pairs) {
			String[] tokens = pair.split("=");
			params.put(tokens[0], tokens[1]);
		}
		
		return params;
	}

	/**
	 * Return the base string ready to be included in signable-string. The difference
	 * between this method and {@link #getSigningBaseURL(String)} is that the return
	 * value will be percent-encoded, if needed.
	 * 
	 * @param baseURL
	 * @return
	 * @throws URISyntaxException 
	 */
	public static String getSignableBase(String url) throws URISyntaxException {
		return UriUtils.encodeURIComponent(getSigningBaseURL(url), true);
	}
	
	/**
	 * Return the base string ready to be included in signable-string. The difference
	 * between this method and {@link #getSigningBaseURL(URI)} is that the return
	 * value will be percent-encoded, if needed.
	 * 
	 * @param uri
	 * @return
	 */
	public static String getSignableBase(URI uri) {
		return UriUtils.encodeURIComponent(getSigningBaseURL(uri), true);
	}
	
	/**
	 * Return the signing base URL that is appended after the HTTP VERB
	 * in OAuth header.
	 * 
	 * @param url
	 * @return
	 * @throws URISyntaxException
	 */
	public static String getSigningBaseURL(String url) throws URISyntaxException {
		if(AssertUtils.isEmpty(url)) {
			throw new IllegalArgumentException("URL cannot be null/empty");
		}
		
		return getSigningBaseURL(new URI(url));
	}
	
	/**
	 * Return the signing base URL that is appended after the HTTP VERB
	 * in OAuth header.
	 * 
	 * @param uri
	 * @return
	 */
	public static String getSigningBaseURL(URI uri) {
		if(uri == null) {
			throw new IllegalArgumentException("URI cannot be null");
		}
		
		StringBuilder builder = new StringBuilder();
		builder.append(uri.getScheme().toLowerCase());
		builder.append("://");
		builder.append(uri.getHost().toLowerCase());
		
		int port = uri.getPort();
		if(port != 80) {
			builder.append(':');
			builder.append(String.valueOf(port));
		}
		
		builder.append(uri.getPath());
		
		return builder.toString();
	}
	
	/**
	 * 
	 * @param endPoint
	 * @param method
	 * @param oAuthHeaderName
	 * @param consumerKey
	 * @param consumerSecret
	 * @param signatureMethod
	 * @param oAuthVersion
	 * @param requestParams
	 * @param includeOAuthParamsInBody
	 * @return
	 */
	public static WebRequest createOAuthRequest(String endPoint, WebRequestMethod method, OAuthSignatureMethod signatureMethod, String oAuthVersion, String oAuthHeaderName, String consumerKey, 
			String consumerSecret, String timestamp, String nonce, Map<String, String> requestParams, boolean includeOAuthParamsInBody) {
		
		StringBuilder builder = new StringBuilder();
		builder.append(method.toString().toUpperCase());
		builder.append("&");
		
		builder.append(UriUtils.encodeURIComponent(endPoint, true));
		
		TreeMap<String, String> params = new TreeMap<String, String>();
		params.put(OAuthConstants.OAUTH_CONSUMER_KEY, consumerKey);
		params.put(OAuthConstants.OAUTH_NONCE, generateNonce());
		params.put(OAuthConstants.OAUTH_SIGNATURE_METHOD, signatureMethod.getOauthName());
		params.put(OAuthConstants.OAUTH_TIMESTAMP, String.valueOf(System.currentTimeMillis()));
		params.put(OAuthConstants.OAUTH_VERSION, oAuthVersion);

		if(AssertUtils.isNotEmpty(requestParams)) {
			for(Entry<String, String> entry : requestParams.entrySet()) {
				params.put(entry.getKey(), entry.getValue());
			}
		}
		
		String paramString = generateParamString(params, true);
		
		builder.append("&");
		builder.append(UriUtils.encodeURIComponent(paramString, true));
		
		System.out.println("Signable: " + builder.toString());
		
		String signature = generateSignature(consumerSecret, "", builder.toString(), signatureMethod);
		params.put(OAuthConstants.OAUTH_SIGNATURE, signature);
		
		// build oauth header
		WebRequest request = WebInvoker.getWebRequest(endPoint, method);
		if(oAuthHeaderName != null) {
			request.addHeader(oAuthHeaderName, "OAuth " + getAllOAuthParams(params));
		}
		
		request.bodyForm(getBodyParams(params, includeOAuthParamsInBody));
		
		return request;
	}
	
	/**
	 * @param endPoint
	 * @param method
	 * @param signatureMethod
	 * @param oAuthVersion
	 * @param authorizationHeader
	 * @param consumerKey
	 * @param consumerSecret
	 * @param tokenKey
	 * @param tokenSecret
	 * @param params
	 * @param includeOAuthParamsInBody
	 * @return
	 */
	public static WebRequest createUserSignedOAuthRequest(String endPoint, WebRequestMethod method, OAuthSignatureMethod signatureMethod, String oAuthVersion, String oAuthHeaderName, String consumerKey, 
			String consumerSecret, String tokenKey, String tokenSecret, String timestamp, String nonce, Map<String, String> requestParams, boolean includeOAuthParamsInBody) {
		
		StringBuilder builder = new StringBuilder();
		builder.append(method.toString().toUpperCase());
		builder.append("&");
		
		builder.append(UriUtils.encodeURIComponent(endPoint, true));
		
		TreeMap<String, String> params = new TreeMap<String, String>();
		params.put(OAuthConstants.OAUTH_CONSUMER_KEY, consumerKey);
		params.put(OAuthConstants.OAUTH_NONCE, generateNonce());
		params.put(OAuthConstants.OAUTH_SIGNATURE_METHOD, signatureMethod.getOauthName());
		params.put(OAuthConstants.OAUTH_TIMESTAMP, String.valueOf(System.currentTimeMillis()));
		params.put(OAuthConstants.OAUTH_VERSION, oAuthVersion);
		params.put(OAuthConstants.OAUTH_TOKEN, tokenKey);

		if(AssertUtils.isNotEmpty(requestParams)) {
			for(Entry<String, String> entry : requestParams.entrySet()) {
				params.put(entry.getKey(), entry.getValue());
			}
		}
		
		String paramString = generateParamString(params, true);
		
		builder.append("&");
		builder.append(UriUtils.encodeURIComponent(paramString, true));
		
		System.out.println("Signable: " + builder.toString());
		
		String signature = generateSignature(consumerSecret, tokenSecret, builder.toString(), signatureMethod);
		params.put(OAuthConstants.OAUTH_SIGNATURE, signature);
		
		// build oauth header
		WebRequest request = WebInvoker.getWebRequest(endPoint, method);
		if(oAuthHeaderName != null) {
			request.addHeader(oAuthHeaderName, "OAuth " + getAllOAuthParams(params));
		}
		
		List<NameValuePair> pairs = getBodyParams(params, includeOAuthParamsInBody);
		if(pairs != null && !pairs.isEmpty()) {
			request.bodyForm(pairs);
		}
		
		return request;
	}
	
	/**
	 * Get a list of all non-aouth params from the given map.
	 * 
	 * @param params
	 * @return
	 */
	private static List<NameValuePair> getBodyParams(TreeMap<String, String> params, boolean includeOAuthParamsInBody) {
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		
		for(Entry<String, String> entry : params.entrySet()) {
			String key = entry.getKey();
			if(!includeOAuthParamsInBody && key.startsWith("oauth_")) {
				continue;
			}
			
			nvps.add(new BasicNameValuePair(key, entry.getValue()));
		}
		
		return nvps;
	}

	/**
	 * Read all oauth params from the given map of parameters.
	 * 
	 * @param params
	 * @param signature
	 * @return
	 */
	private static String getAllOAuthParams(TreeMap<String, String> params) {
		StringBuilder builder = new StringBuilder();
		boolean first = true;
		
		for(String key : params.keySet()) {
			if(!key.startsWith("oauth_")) {
				continue;
			}
			
			if(!first) {
				builder.append(',');
			} else {
				first = false;
			}
			
			builder.append(key);
			builder.append("=\"");
			builder.append(UriUtils.encodeURIComponent(params.get(key), true));
			builder.append('"');
		}
		
		return builder.toString();
	}
	
	/**
	 * 
	 * @param consumer
	 * @param userToken
	 * @param signable
	 * @param signingMethod
	 * @return
	 */
	public static String generateSignature(OAuthToken consumer, OAuthToken userToken, String signable, OAuthSignatureMethod signingMethod) {
		return generateSignature(consumer.getSecret(), userToken.getSecret(), signable, signingMethod);
	}

	/**
	 * Generate an OAUTH signature for the given signature string.
	 * 
	 * @param consumerKey
	 * 
	 * @param consumerSecret
	 * 
	 * @param signable
	 * 
	 * @return
	 */
	public static String generateSignature(String consumerSecret, String tokenSecret, String signable, OAuthSignatureMethod signingMethod) {
		if(AssertUtils.isEmpty(consumerSecret)) {
			throw new IllegalArgumentException("Signature string cannot be null/empty");
		}
		
		if(AssertUtils.isEmpty(signable)) {
			throw new IllegalArgumentException("Signable string cannot be null/empty");
		}
		
		return doSigning(signable, UriUtils.encodeURIComponent(consumerSecret, true) + "&" + UriUtils.encodeURIComponent(tokenSecret, true), signingMethod);
	}
	
	/**
	 * Generate the signature using the given signing method for the signable using the key string. For OAuth the key
	 * string should already be URI-percent-encoded if need be.
	 * 
	 * @param toSign
	 * @param keyString
	 * @param method
	 * @return
	 */
	public static String doSigning(String signable, String keyString, OAuthSignatureMethod signingMethod) {
		SecretKeySpec key = new SecretKeySpec((keyString).getBytes(StringUtils.CHARSET_UTF8), signingMethod.getAlgorithmName());
		Mac mac;
		try {
			mac = Mac.getInstance(signingMethod.getAlgorithmName());
			mac.init(key);
			byte[] bytes = mac.doFinal(signable.getBytes(StringUtils.CHARSET_UTF8));
			return Base64Encoder.encodeToString(bytes, false);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	/**
	 * Generate a sorted parameter string for the given parameters.
	 * 
	 * 
	 * @param params
	 * @return
	 */
	public static String generateParamString(TreeMap<String, String> params, boolean encodeParamValues) {
		StringBuilder builder = new StringBuilder();
		boolean first = true;
		
		for(String key : params.keySet()) {
			if(first) {
				first = false;
			} else {
				builder.append('&');
			}
			
			builder.append(key);
			builder.append("=");
			if(encodeParamValues) {
				builder.append(UriUtils.encodeURIComponent(params.get(key), true));
			} else {
				builder.append(params.get(key));
			}
		}
		
		return builder.toString();
	}

	/**
	 * Method that generates a NONCE string based on a randomly generated UUID 
	 * and current millis and nano timestamp.
	 * 
	 * @return
	 */
	public static String generateNonce() {
		UUID uuid = UUID.randomUUID();
		return Base62Encoder.encode(uuid.getMostSignificantBits(), uuid.getLeastSignificantBits(), System.currentTimeMillis(), System.nanoTime());
	}

}
