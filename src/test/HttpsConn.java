package test;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpsConn {
	public static void main(String[] arg){
		try {
			URL url = new URL("https://www.baidu.com/");
			HttpsURLConnection connection = (HttpsURLConnection)url.openConnection();
			SSLContext sc =  SSLContext.getInstance("TLS");
			sc.init(null, new TrustManager[] {new MyTrust()}, new java.security.SecureRandom());
			connection.setSSLSocketFactory(sc.getSocketFactory());
			connection.connect();
//			BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(),"UTF-8"));
//			String line;
//			while((line = br.readLine())!=null) {
//				System.out.println(line);
//			}
			SSLSessionContext scc = sc.getClientSessionContext();
			SSLSessionContext scs = sc.getServerSessionContext();
//			SSLSession sc = scc.getSession(new byte[]);
//			Enumeration<byte[]>	   getIds()
			Enumeration<byte[]> id_c = scc.getIds();
			Enumeration<byte[]> id_s = scs.getIds();
			byte[] b1 = null;	
			byte[] b2 = null;
//			while(id_c.hasMoreElements()) {
				b1 = id_c.nextElement();
//				b2 = id_s.nextElement();
//				for (byte x:b) {
//					System.out.print(Byte.toString(x)+",");
//				}
//			}
			SSLSession ss = scc.getSession(b1);
			System.out.println(ss.getCipherSuite());
			System.out.println(ss.getLocalCertificates());
			System.out.println(ss.getPeerCertificates());
			System.out.println(ss.getPeerCertificateChain());
			System.out.println(ss.getPeerCertificates()[0].toString());
			System.out.println("===================================");
			System.out.println(ss.getPeerCertificateChain()[0].toString());

			
		} catch (MalformedURLException e) {
			System.out.println("new URL");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("url.openConnection");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("SSLContext.getInstance");
			e.printStackTrace();
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
}


class SessionContext implements SSLSessionContext{

	public Enumeration<byte[]> getIds() {return null;}

	public SSLSession getSession(byte[] arg0) {
		// TODO Auto-generated method stub
		return null;
	}
	public int getSessionCacheSize() {return 0;	}
	public int getSessionTimeout() {return 0;	}
	public void setSessionCacheSize(int arg0) throws IllegalArgumentException {}
	public void setSessionTimeout(int arg0) throws IllegalArgumentException {}	
}

class MyTrust implements X509TrustManager{
	public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
	public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
	public X509Certificate[] getAcceptedIssuers() {return null;	}	
}
