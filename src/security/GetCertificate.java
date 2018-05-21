package security;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
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

public class GetCertificate {
    
    static boolean frame;
//  public static File file = null;
    private static String[] ip_seg = null;
    private static int seg3;
    static URL url = null;
    private static int cnt; //IP与证书里的IP不一样的个数，应该为0。
    private static int cnt_total; //已读证书个数。

    public static void checkCert() {
        cnt_total = 0;
        ip_seg = FrameSecurity.host.split("[.]");
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
        if (FrameSecurity.host != null) {
            frame = true;}
        try {
            /*if(Frame.ForFun) {
                url = new URL(Frame.ip);
                SocketAddress sa = new InetSocketAddress("140.231.235.4",8080);     //使用代理
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
                
//          BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(),"UTF-8"));
//          String line;
//          while((line = br.readLine())!=null) {
//              System.out.println(line);
//          }
            //SSLContext的实例表示安全套接字协议的实现，用作（安全套接字工厂或SSLEngine)的工厂。 sc已经用自定的密钥，信任管理器和随机数初始化，所以
            //可以读它的一些属性，比如安全套接字协议、安全套接字工厂、SSLSessionContext等。
            //SSLSessionContext表示一组(a set of)与单个实体关联的SSL 会话。比如一个SSLSessionContext的实例可以关联到一个客户端或服务端,此客户端或服务端 在并行多个会话。
            //用 getIds()获得此SSLSessionContext的(枚举类)所有并行会话的ID。
            SSLSessionContext scc = sc.getClientSessionContext();
            Enumeration<byte[]> id_c = scc.getIds();
            byte[] b1 = id_c.nextElement();//确定有且只有一个证书ID，所以直接访问nextElement().其它情况要用while(hasMoreElements)
            SSLSession sslSession = scc.getSession(b1);
            X509Certificate cert = null;
            cert = (X509Certificate) sslSession.getPeerCertificates()[0];//确定有且只有一个证书ID，所以直接访问证书数组[0]
            javax.security.cert.X509Certificate[] certChain = sslSession.getPeerCertificateChain();
            
            if(FrameSecurity.tls) ((HttpsURLConnection) connection).disconnect();
            
            if(cert == null) {
                FrameSecurity.updateTextArea("Get certificate error!");
            }else {
                cnt_total++;
//              FrameSecurity.updateTextAreacnt(cnt_total);
            }
            
            System.out.println("CipherSuite: "+sslSession.getCipherSuite());
            System.out.println("LocalCertificates: "+sslSession.getLocalCertificates());//读不到东西.
            System.out.println("PeerCertificates: "+sslSession.getPeerCertificates());
            System.out.println("PeerCertificateChain: "+sslSession.getPeerCertificateChain());
            if(FrameSecurity.save) {
                if(!FrameSecurity.certSegment) {
                    File file = new File("cert.txt");
                    FileOutputStream fos = new FileOutputStream(file);
                    PrintWriter pw = new PrintWriter(fos);
                    pw.write(cert.toString());
                    pw.close();
//                    ObjectOutputStream oos = new ObjectOutputStream(fos);
//                    oos.writeObject(cert);
//                    oos.flush();
//                    oos.close();
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
//          System.out.println("x509Certificate_getIssuerDN_发布方标识名___:"+cert.getIssuerX500Principal());   
//          if(frame) 
//              Frame.updateTextArea("Issuer: "+cert.getIssuerX500Principal()+"\n");  
            /*System.out.println("x509Certificate_getSubjectDN_主体标识___:"+cert.getSubjectX500Principal());  
            System.out.println("x509Certificate_getSigAlgOID_证书算法OID字符串___:"+cert.getSigAlgOID()); 
            System.out.println("x509Certificate_getNotBefore_证书起始期___:"+cert.getNotBefore()); */
            if(frame) 
                FrameSecurity.updateTextArea("Sigurature validation after: "+cert.getNotBefore()+"\n");
            System.out.println("x509Certificate_getNotBefore_证书有效期___:"+cert.getNotAfter()); 
//          if(frame) 
//              Frame.updateTextArea("Sigurature validation before: "+cert.getNotAfter()+"\n");
            System.out.println("x509Certificate_getSigAlgName_签名算法___:"+cert.getSigAlgName());  
            if(frame) 
                FrameSecurity.updateTextArea("Sigurature algrithm: "+cert.getSigAlgName()+"\n");
            System.out.println("x509Certificate_getVersion_版本号___:"+cert.getVersion());  
//          System.out.println("x509Certificate_getPublicKey_公钥___:"+cert.getPublicKey());  
            Collection<List<?>> subject = cert.getSubjectAlternativeNames();
            String ip = subject.toString().substring(5, subject.toString().length()-2);
            System.out.println(ip);
            if(frame) 
                FrameSecurity.updateTextArea("Subject ip: "+ip+"\n");
			if (!FrameSecurity.ForFun) {
				// String str = "https://" + FrameSecurity.ip + "/home";
				// str = str.substring(8, str.length());//去掉前面八个字符(https://)
				// int i = str.indexOf("/");
				// str = str.substring(0, i);
				String str = ip_seg[0] + "." + ip_seg[1] + "." + ip_seg[2] + "." + tmp;
				if (!ip.equals(str)) {
					if (frame)
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
            FrameSecurity.updateTextArea("Connection not established. (Last segment of IP addr: " + tmp +" )\nIf the IP is correct, try again or check it via browser.\n");
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
//  public Enumeration<byte[]> getIds() {return null;}
//
//  public SSLSession getSession(byte[] arg0) {
//      return null;
//  }
//  public int getSessionCacheSize() {return 0; }
//  public int getSessionTimeout() {return 0;   }
//  public void setSessionCacheSize(int arg0) throws IllegalArgumentException {}
//  public void setSessionTimeout(int arg0) throws IllegalArgumentException {}  
//}

//class MyTrust implements X509TrustManager{
//  public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
//  public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
//  public X509Certificate[] getAcceptedIssuers() {return null; }   
//}
