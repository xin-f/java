package security;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class GetCertificate {
	public static void main(String[] arg){
		try {
			URL url = new URL("https://172.20.1.24/home");
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
			Enumeration<byte[]> id_c = scc.getIds();
//			Enumeration<byte[]> id_s = scs.getIds();
			byte[] b1 = id_c.nextElement();//确定有且只有一个证书ID，所以直接访问nextElement().其它情况要用while(hasMoreElements)
			SSLSession sslSession = scc.getSession(b1);
			X509Certificate cert = (X509Certificate) sslSession.getPeerCertificates()[0];//确定有且只有一个证书ID，所以直接访问证书数组[0]
			System.out.println(sslSession.getCipherSuite());
			System.out.println(sslSession.getLocalCertificates());//读不到东西.
			System.out.println(sslSession.getPeerCertificates());
			System.out.println(sslSession.getPeerCertificateChain());
//			FileOutputStream fos = new FileOutputStream("aaa.txt");
//			PrintWriter pw = new PrintWriter(fos);
//			pw.write(cert.toString());
//			pw.close();
//			fos.close();
			
			byte[] serial = cert.getSerialNumber().toByteArray();  
			Formatter serialN = new Formatter();
			for(byte b:serial) {
				serialN.format("%2X:", b);
			}
			String serialNum = serialN.toString().substring(0,serialN.toString().length()-1);
			System.out.println(serialNum);
	        System.out.println("x509Certificate_SerialNumber_序列号___:"+cert.getSerialNumber());  
	        System.out.println("x509Certificate_getIssuerDN_发布方标识名___:"+cert.getIssuerX500Principal());   
	        System.out.println("x509Certificate_getSubjectDN_主体标识___:"+cert.getSubjectX500Principal());  
	        System.out.println("x509Certificate_getSigAlgOID_证书算法OID字符串___:"+cert.getSigAlgOID());  
	        System.out.println("x509Certificate_getNotBefore_证书有效期___:"+cert.getNotAfter());  
	        System.out.println("x509Certificate_getSigAlgName_签名算法___:"+cert.getSigAlgName());  
	        System.out.println("x509Certificate_getVersion_版本号___:"+cert.getVersion());  
	        System.out.println("x509Certificate_getPublicKey_公钥___:"+cert.getPublicKey());  
	        Collection<List<?>> subject = cert.getSubjectAlternativeNames();
	        String ip = subject.toString().substring(5, subject.toString().length()-2);
	        System.out.println(ip);
	        byte[] sig = cert.getSignature();
	        Formatter sign = new Formatter();
	        for(byte b:sig)
	        	sign.format("%02X:",b);
	        String signature = sign.toString().substring(0, sign.toString().length()-1);
	        System.out.println(signature);

			
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
		} catch (CertificateParsingException e) {
			System.out.println("getSubjectAlternativeNames)");
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
