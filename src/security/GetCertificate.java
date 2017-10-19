package security;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class GetCertificate {
	
	static boolean frame;
//	public static File file = null;
	private static String[] ip_seg = null;
	private static int seg3;
    static URL url = null;
    private static int cnt; //IP��֤�����IP��һ���ĸ�����Ӧ��Ϊ0��
    private static int cnt_total; //�Ѷ�֤�������

    public static void checkCert() {
        cnt_total = 0;
        ip_seg = FrameSecurity.ip.split("[.]");
        seg3 = Integer.parseInt(ip_seg[3]);
        if (!FrameSecurity.certSegment) {
            check(seg3);
        } else {
            if (seg3 > FrameSecurity.certEnd)
                FrameSecurity.updateTextArea("The END ip value should be larger than the START one.\n");
            else {
                for (int i = seg3; i <= FrameSecurity.certEnd; i++) {
                    check(i);
                }
            }
        }
    }

	public static void check(int tmp){
		frame = false;
		if(FrameSecurity.ip != null)
			frame = true;
		try {
			/*if(Frame.ForFun) {
				url = new URL(Frame.ip);
				SocketAddress sa = new InetSocketAddress("140.231.235.4",8080);		//ʹ�ô���
				Proxy proxy = new Proxy(Proxy.Type.HTTP,sa);
				connection = (HttpsURLConnection)url.openConnection(proxy);
			}		
			else {*/
			url = new URL("https://" + ip_seg[0] + "." + ip_seg[1] + "." + ip_seg[2] + "." + tmp + "/home");
			URLConnection connection = url.openConnection();
			SSLContext sc =  SSLContext.getInstance("TLS");
			sc.init(null, new TrustManager[] {new MyTrust()}, new java.security.SecureRandom());
			if(FrameSecurity.tls) {
				((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
				connection.setConnectTimeout(1000);
				connection.connect();
			}
				
//			BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(),"UTF-8"));
//			String line;
//			while((line = br.readLine())!=null) {
//				System.out.println(line);
//			}
			//SSLContext��ʵ����ʾ��ȫ�׽���Э���ʵ�֣���������ȫ�׽��ֹ�����SSLEngine)�Ĺ����� sc�Ѿ����Զ�����Կ�����ι��������������ʼ��������
			//���Զ�����һЩ���ԣ����簲ȫ�׽���Э�顢��ȫ�׽��ֹ�����SSLSessionContext�ȡ�
			//SSLSessionContext��ʾһ��(a set of)�뵥��ʵ�������SSL �Ự������һ��SSLSessionContext��ʵ�����Թ�����һ���ͻ��˻�����,�˿ͻ��˻����� �ڲ��ж���Ự��
			//��	getIds()��ô�SSLSessionContext��(ö����)���в��лỰ��ID��
			SSLSessionContext scc = sc.getClientSessionContext();
			Enumeration<byte[]> id_c = scc.getIds();
			byte[] b1 = id_c.nextElement();//ȷ������ֻ��һ��֤��ID������ֱ�ӷ���nextElement().�������Ҫ��while(hasMoreElements)
			SSLSession sslSession = scc.getSession(b1);
			X509Certificate cert = null;
			cert = (X509Certificate) sslSession.getPeerCertificates()[0];//ȷ������ֻ��һ��֤��ID������ֱ�ӷ���֤������[0]
			javax.security.cert.X509Certificate[] certChain = sslSession.getPeerCertificateChain();
			
			if(FrameSecurity.tls) ((HttpsURLConnection) connection).disconnect();
			
			if(cert == null) {
			    FrameSecurity.updateTextArea("Get certificate error!");
			}else {
			    cnt_total++;
//			    FrameSecurity.updateTextAreacnt(cnt_total);
			}
			
			System.out.println(sslSession.getCipherSuite());
			System.out.println(sslSession.getLocalCertificates());//����������.
			System.out.println(sslSession.getPeerCertificates());
			System.out.println(sslSession.getPeerCertificateChain());
			if(FrameSecurity.save) {
			    if(!FrameSecurity.certSegment) {
			        File file = new File("cert.txt");
	                FileOutputStream fos = new FileOutputStream(file);
	                PrintWriter pw = new PrintWriter(fos);
	                pw.write(cert.toString());
	                pw.close();
	                fos.close(); 
			    }else {
			        File file = new File("cert_" + tmp + ".txt");
	                FileOutputStream fos = new FileOutputStream(file);
	                PrintWriter pw = new PrintWriter(fos);
	                pw.write(cert.toString());
	                pw.close();
	                fos.close();
			    }			    
			}			
			
			byte[] serial = cert.getSerialNumber().toByteArray();  
			Formatter serialN = new Formatter();
			for(byte b:serial) {
				serialN.format("%02X:", b);
			}
			String serialNum = serialN.toString().substring(0,serialN.toString().length()-1);
			System.out.println(serialNum);
			if(frame) 
				FrameSecurity.updateTextArea("Serial Number: "+serialNum+"\n");
			serialN.close(); 
//	        System.out.println("x509Certificate_getIssuerDN_��������ʶ��___:"+cert.getIssuerX500Principal());   
//	        if(frame) 
//	        	Frame.updateTextArea("Issuer: "+cert.getIssuerX500Principal()+"\n");  
	        /*System.out.println("x509Certificate_getSubjectDN_�����ʶ___:"+cert.getSubjectX500Principal());  
	        System.out.println("x509Certificate_getSigAlgOID_֤���㷨OID�ַ���___:"+cert.getSigAlgOID()); 
	        System.out.println("x509Certificate_getNotBefore_֤����ʼ��___:"+cert.getNotBefore()); */
	        if(frame) 
	        	FrameSecurity.updateTextArea("Sigurature validation after: "+cert.getNotBefore()+"\n");
	        System.out.println("x509Certificate_getNotBefore_֤����Ч��___:"+cert.getNotAfter()); 
//	        if(frame) 
//	        	Frame.updateTextArea("Sigurature validation before: "+cert.getNotAfter()+"\n");
	        System.out.println("x509Certificate_getSigAlgName_ǩ���㷨___:"+cert.getSigAlgName());  
	        if(frame) 
	        	FrameSecurity.updateTextArea("Sigurature algrithm: "+cert.getSigAlgName()+"\n");
	        System.out.println("x509Certificate_getVersion_�汾��___:"+cert.getVersion());  
//	        System.out.println("x509Certificate_getPublicKey_��Կ___:"+cert.getPublicKey());  
	        Collection<List<?>> subject = cert.getSubjectAlternativeNames();
	        String ip = subject.toString().substring(5, subject.toString().length()-2);
	        System.out.println(ip);
	        if(frame) 
	        	FrameSecurity.updateTextArea("Subject ip: "+ip+"\n");
	        if(!FrameSecurity.ForFun) {	
//	        	String str = "https://" + FrameSecurity.ip + "/home";
//	        	str = str.substring(8, str.length());//ȥ��ǰ��˸��ַ�(https://)
//	        	int i = str.indexOf("/");
//	        	str = str.substring(0, i);
	            String str = ip_seg[0] + "." + ip_seg[1] + "." + ip_seg[2] + "." + tmp;
	        	if(!ip.equals(str))
		        	{if(frame)
		        		FrameSecurity.updateTextArea("Wrong!! Certificate not updated!\n");
		        	cnt++;
		        	FrameSecurity.updateTextAreacnt(cnt);
		        	}
	        }		        
	        byte[] sig = cert.getSignature();
	        Formatter sign = new Formatter();
	        for(byte b:sig)
	        	sign.format("%02X:",b);
	        String signature = sign.toString().substring(0, sign.toString().length()-1);
	        System.out.println(signature);
	        sign.close();
	        if(frame)
        		{
	            FrameSecurity.updateTextArea("Signature: "+signature+"\n");
	            FrameSecurity.updateTextArea(cnt_total+" certificate(s) got.\n");
	            FrameSecurity.updateTextArea("=============================\n");
        		}
			FrameSecurity.chkRunning = false;
		} catch (MalformedURLException e) {
			System.out.println("new URL");
			FrameSecurity.updateTextArea("Connection not established.\nIf it's a webserver, input complete URL\n");
			e.printStackTrace();
		} catch (IOException e) {
			FrameSecurity.updateTextArea("Connection not established.\nIf the IP is correct, try again or check it via browser.\n");
			System.out.println("url.openConnection");
			FrameSecurity.updateTextArea("=============================\n");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("SSLContext.getInstance");
			e.printStackTrace();
		} catch (KeyManagementException e) {
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
//		return null;
//	}
//	public int getSessionCacheSize() {return 0;	}
//	public int getSessionTimeout() {return 0;	}
//	public void setSessionCacheSize(int arg0) throws IllegalArgumentException {}
//	public void setSessionTimeout(int arg0) throws IllegalArgumentException {}	
//}

//class MyTrust implements X509TrustManager{
//	public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
//	public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
//	public X509Certificate[] getAcceptedIssuers() {return null;	}	
//}
