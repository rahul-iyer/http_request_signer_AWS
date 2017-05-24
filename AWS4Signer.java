import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;





public class AWS4Signer {
	
	public AWS4Signer(String access_key,String secretkey,String endpoint,String method,String region,String service, String request_parameters) throws MalformedURLException, URISyntaxException{
		this.access_key = access_key;
		this.secretkey = secretkey;
	    URI uri = new URI(endpoint);

		this.host = uri.getHost();
		this.cannonical_uri = uri.getPath();
		this.method = method;
		this.region = region;
		this.service = service;
		this.request_parameters = this.request_parameters;
	}

	public byte[] HmacSHA256(String data, byte[] key) {
	    String algorithm="HmacSHA256";
	    Mac mac;
		try {
			mac = Mac.getInstance(algorithm);
			mac.init(new SecretKeySpec(key, algorithm));
		    return mac.doFinal(data.getBytes("UTF8"));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	    
	}
	private String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}

	public byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName){
	    byte[] kSecret;
		try {
			kSecret = ("AWS4" + key).getBytes("UTF8");
			byte[] kDate = HmacSHA256(dateStamp, kSecret);
		    byte[] kRegion = HmacSHA256(regionName, kDate);
		    byte[] kService = HmacSHA256(serviceName, kRegion);
		    byte[] kSigning = HmacSHA256("aws4_request", kService);
		    return kSigning;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		}
		return null;
	    
	    
	}
	String access_key = this.access_key;
	String secretkey = this.secretkey;
	String host = this.host;;
	String method = this.method;
	String region = this.region;
	String service = this.service;
	String cannonical_uri= this.cannonical_uri;
	String request_parameters = this.request_parameters;
	
	private String getTimeStamp(Date date) {
        DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"))
        return dateFormat.format(date);
    }
	private String getDate11(Date date) {
        DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"))
        return dateFormat.format(date);
    }
    // Add other headers if needed in alphabetical order

	private String prepareCanonicalHeader(String datestamp){
		StringBuilder canonicalRequest = new StringBuilder("");
		if(method == "POST" || method == "PUT"){
		canonicalRequest.append("content-type:").append("application/json").append("\n");
		}
		canonicalRequest.append("host:").append(host).append("\n");
		canonicalRequest.append("x-amz-date:").append(datestamp).append("\n");
		
		return canonicalRequest.toString();
	}
	private String getMessageDigest(String payload){
		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		digest.update(payload.getBytes());
		StringBuffer result = new StringBuffer();
	    for (byte b : digest.digest()) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
	    return result.toString();
		
	}
	public HashMap<String,String> sign(){
	Date date = new Date();
	String amzDate = getTimeStamp(date);
	String datestamp = getDate11(date);
	String canonical_querystring = ""; // handle this appropriately if you have any query parameters
	String canonical_headers = prepareCanonicalHeader(amzDate);
	String signed_headers = "";
	// Add other headers if needed in alphabetical order
	if(method == "POST" || method == "PUT"){
		signed_headers = signed_headers+ "content-type;";
	}

	signed_headers = signed_headers+ "host;x-amz-date";
	String payload_hash = getMessageDigest(request_parameters);
	
	String canonical_request = new StringBuilder(method).append("\n").append(cannonical_uri).append("\n").
											append(canonical_querystring).append("\n").append(canonical_headers).
											append("\n").append(signed_headers).
											append("\n").append(payload_hash).toString();
	
	String algorithm = "AWS4-HMAC-SHA256";
	String credential_scope = datestamp + "/" + region + "/" + service + "/" + "aws4_request";
	String string_to_sign = algorithm + "\n" + amzDate + "\n" + credential_scope + "\n" + getMessageDigest(canonical_request);
	
	byte[] signing_key = getSignatureKey(secretkey, datestamp,region,service);
	byte[] signature = HmacSHA256(string_to_sign,signing_key );
	
	String authorization_header= algorithm + " " + "Credential=" + access_key + "/" + credential_scope + ", " + "SignedHeaders=" + signed_headers + ", " + "Signature=" + toHexString(signature);
	
	HashMap <String,String> auth_headers = new HashMap<String,String>();
	
	auth_headers.put("Authorization",authorization_header);
	auth_headers.put("x-amz-date", amzDate);
	
	return auth_headers;
	}

} 
	
	