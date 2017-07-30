package test;

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
//			Enumeration<byte[]> id_s = scs.getIds();
			byte[] b1 = null;	
			byte[] b2 = null;
//			while(id_c.hasMoreElements()) {
				b1 = id_c.nextElement();
//				b2 = id_s.nextElement();
//				for (byte x:b) { 
//					System.out.print(Byte.toString(x)+",");
//				}
//			}
			FileOutputStream fos = new FileOutputStream("aaa.txt");
			PrintWriter pw = new PrintWriter(fos);
			SSLSession sslSession = scc.getSession(b1);
			X509Certificate cert = (X509Certificate) sslSession.getPeerCertificates()[0];
			System.out.println(sslSession.getCipherSuite());
			System.out.println(sslSession.getLocalCertificates()+"  l");//读不到东西.
			System.out.println(sslSession.getPeerCertificates()+"   p");
			System.out.println(sslSession.getPeerCertificateChain());
//			System.out.println(ss.getPeerCertificates()[0].toString());
//			System.out.println("===================================");
//			System.out.println(ss.getPeerCertificateChain()[0].toString());
//			pw.write(ss.getPeerCertificates()[0].toString());
//			pw.close();
//			fos.close();
			System.out.println("读取Cer证书信息");  
	        System.out.println("x509Certificate_SerialNumber_序列号___:"+cert.getSerialNumber());  
	        System.out.println("x509Certificate_getIssuerDN_发布方标识名___:"+cert.getIssuerDN());   
	        System.out.println("x509Certificate_getSubjectDN_主体标识___:"+cert.getSubjectDN());  
	        System.out.println("x509Certificate_getSigAlgOID_证书算法OID字符串___:"+cert.getSigAlgOID());  
	        System.out.println("x509Certificate_getNotBefore_证书有效期___:"+cert.getNotAfter());  
	        System.out.println("x509Certificate_getSigAlgName_签名算法___:"+cert.getSigAlgName());  
	        System.out.println("x509Certificate_getVersion_版本号___:"+cert.getVersion());   
	        //http://blog.csdn.net/oguro/article/details/53086720 接口实现多态
	        //http://blog.csdn.net/fegor/article/details/1559404 多态
	        System.out.println("x509Certificate_getPublicKey_公钥___:"+cert.getPublicKey()); 

			
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
