package security;

import java.net.HttpURLConnection;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;

//public class CommonSetting{}

public class MyTrust implements X509TrustManager{
	public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
	public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
	public X509Certificate[] getAcceptedIssuers() {return null;	}	
}

