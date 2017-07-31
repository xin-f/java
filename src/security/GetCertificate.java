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
	static boolean frame;
	public static void main(String[] arg){
		if(Frame.ip == null)
			checkCert();
	}
	public static void checkCert(){
		frame = false;
		if(Frame.ip != null)
			frame = true;
		try {
			URL url = new URL("https://"+Frame.ip+"/home");
//			URL url = new URL("https://www.baidu.com");
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
			//SSLContext的实例表示安全套接字协议的实现，用作（安全套接字工厂或SSLEngine)的工厂。 sc已经用自定的密钥，信任管理器和随机数初始化，所以
			//可以读它的一些属性，比如安全套接字协议、安全套接字工厂、SSLSessionContext等。
			//SSLSessionContext表示一组(a set of)与单个实体关联的SSL 会话。比如一个SSLSessionContext的实例可以关联到一个客户端或服务端,此客户端或服务端 在并行多个会话。
			//用	getIds()获得此SSLSessionContext的(枚举类)所有并行会话的ID。
			SSLSessionContext scc = sc.getClientSessionContext();
			Enumeration<byte[]> id_c = scc.getIds();
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
			if(frame) 
				Frame.updateTextArea("Serial Number: "+serialNum+"\n");
			serialN.close(); 
	        System.out.println("x509Certificate_getIssuerDN_发布方标识名___:"+cert.getIssuerX500Principal());   
	        if(frame) 
	        	Frame.updateTextArea("Issuer: "+cert.getIssuerX500Principal()+"\n");  
	        System.out.println("x509Certificate_getSubjectDN_主体标识___:"+cert.getSubjectX500Principal());  
	        System.out.println("x509Certificate_getSigAlgOID_证书算法OID字符串___:"+cert.getSigAlgOID());  
	        System.out.println("x509Certificate_getNotBefore_证书有效期___:"+cert.getNotAfter());  
	        System.out.println("x509Certificate_getSigAlgName_签名算法___:"+cert.getSigAlgName());  
	        if(frame) 
	        	Frame.updateTextArea("Sigurature algrithm: "+cert.getSigAlgName()+"\n");
	        System.out.println("x509Certificate_getVersion_版本号___:"+cert.getVersion());  
	        System.out.println("x509Certificate_getPublicKey_公钥___:"+cert.getPublicKey());  
	        Collection<List<?>> subject = cert.getSubjectAlternativeNames();
	        String ip = subject.toString().substring(5, subject.toString().length()-2);
	        System.out.println(ip);
	        if(frame) 
	        	Frame.updateTextArea("Subject ip: "+ip+"\n");
	        if(!ip.equals(Frame.ip))
	        	if(frame)
	        		Frame.updateTextArea("Wrong!! Certificate not updated!\n");
	        byte[] sig = cert.getSignature();
	        Formatter sign = new Formatter();
	        for(byte b:sig)
	        	sign.format("%02X:",b);
	        String signature = sign.toString().substring(0, sign.toString().length()-1);
	        System.out.println(signature);
	        sign.close();
	        if(frame)
        		Frame.updateTextArea("Signature: "+signature+"\n");
			
		} catch (MalformedURLException e) {
			System.out.println("new URL");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("url.openConnection");
			Frame.updateTextArea("Connection not established.\nIf the IP is correct, try again or check it via browser.\n ");
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


//class SessionContext implements SSLSessionContext{
//
//	public Enumeration<byte[]> getIds() {return null;}
//
//	public SSLSession getSession(byte[] arg0) {
//		// TODO Auto-generated method stub
//		return null;
//	}
//	public int getSessionCacheSize() {return 0;	}
//	public int getSessionTimeout() {return 0;	}
//	public void setSessionCacheSize(int arg0) throws IllegalArgumentException {}
//	public void setSessionTimeout(int arg0) throws IllegalArgumentException {}	
//}

class MyTrust implements X509TrustManager{
	public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
	public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
	public X509Certificate[] getAcceptedIssuers() {return null;	}	
}
