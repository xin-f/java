package security;


import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class Common {
    
    public static String boundary = "----thisisfromEn100securityteam-sunxinfeng";
    public static SSLContext sc = null;
    public String pwExistAlready = "Confirm new password:"; //静态查询是否存在密码，只用一次。动态反馈密码是否设成功用 pwSet
    public boolean pwExist;      //密码已设置
    public static BufferedReader in = null;
    public static URLConnection connection = null;
    public static BufferedOutputStream out;
    public static String[] host_seg;
    public static String isOn = "value=\"1\""; //TCP, DTLS的状态
    public static String isOff = "value=\"0\"";

    /*public static void checkCurrent(String link) {
        Common.host_seg = FrameSecurity.host.split("[/]");
        try {
            Common.url = new URL(Common.host_seg[0]+"/"+Common.host_seg[1]+"/"+Common.host_seg[2]+link+"/setupsecureengineeringaccess");
            Common.setConnection(Common.url);
            String str;
            BufferedReader in = new BufferedReader(new InputStreamReader(Common.connection.getInputStream()));
            while ((str = in.readLine()) != null) {
                if (str.indexOf(isOn) > -1) {
                    if(link.equals("/setupsecureengineeringaccess")) {
                        System.out.println("ison_dtls");
                        FrameSecurity.rdbtnDTLSOn.setSelected(true);
//                        FrameSecurity.rdbtnDTLSOff.setSelected(false);
                        FrameSecurity.rdbtnDTLSOn.paintImmediately(FrameSecurity.rdbtnDTLSOn.getBounds());
                    }
                    if(link.equals("/setupwebmonitoraccess")) {
                        System.out.println("ison_webmon");
                        FrameSecurity.rdbtnTCPOn.setSelected(true);
//                        FrameSecurity.rdbtnTcpOff.setSelected(false);
                        FrameSecurity.rdbtnTCPOn.paintImmediately(FrameSecurity.rdbtnTCPOn.getBounds());
                    }
                }
                if (str.indexOf(isOff) > -1) {
                    if(link.equals("/setupsecureengineeringaccess")) {
                        System.out.println("isoff_dtls");
                        FrameSecurity.rdbtnDTLSOn.setSelected(false);
                        FrameSecurity.rdbtnDTLSOn.paintImmediately(FrameSecurity.rdbtnDTLSOn.getBounds());
                    }
                    if(link.equals("/setupwebmonitoraccess")) {
                        System.out.println("isoff_webmon");
                        FrameSecurity.rdbtnTCPOn.setSelected(false);
                        FrameSecurity.rdbtnTCPOn.paintImmediately(FrameSecurity.rdbtnTCPOn.getBounds());
                    }
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/
    
    public static URLConnection setConnection(URL url) {
        URLConnection connection = null;
        try {
            if (FrameSecurity.tls) {
                connection = Common.setHttpsConnect((HttpsURLConnection) url.openConnection());
                Common.sc = SSLContext.getInstance("TLS");
                Common.sc.init(null, new TrustManager[] { new MyTrust() }, new java.security.SecureRandom());
                ((HttpsURLConnection) connection).setSSLSocketFactory(Common.sc.getSocketFactory());
            } else {
                connection = Common.setHttpConnect((HttpURLConnection) url.openConnection());
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        return connection;
    }
    
/*
    public static boolean checkPasswordExistOrNot(URL url) {
        boolean exist = false;
        String[] seg;
        URLConnection conn = null;
        try {
            String str = null;
            SSLContext sc;
            if (FrameSecurity.tls) {
                conn = Common.setHttpsConnect((HttpsURLConnection) url.openConnection());
                sc = SSLContext.getInstance("TLS");
                sc.init(null, new TrustManager[] { new MyTrust() }, new java.security.SecureRandom());
                ((HttpsURLConnection) conn).setSSLSocketFactory(sc.getSocketFactory());
            } else {
                conn = Common.setHttpConnect((HttpURLConnection) url.openConnection());
            }
            System.out.println("Checking whether password exists in: " + url.toString() + " "+Thread.currentThread().getName());
            conn.setDoInput(true);
            conn.setDoOutput(true);
            
            //必须要自定义一个inputstream的reader，不然在多线程时，所有连接的输入流都混到一个连接。
            System.out.println("The connection in use: "+conn.toString()+" "+Thread.currentThread().getName());
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            while ((str = in.readLine()) != null) {
                if (str.indexOf(pwExistAlready) > -1) { // 一检测到相关字符串,就认为密码已经存在.
                    seg = url.toString().split("[/]");
                    if (seg[3].indexOf("connection") > -1) {
                        FrameSecurity.updateTextArea("DIGSI conn pw exists in EN100." + seg[2] + "\n");
                    }
                    if (seg[3].indexOf("maintenance") > -1) {
                        FrameSecurity.updateTextArea("Maintenance pw exists in EN100." + seg[2] + "\n");
                    }
                    exist = true;
                    break;
                }
            }
            if (FrameSecurity.tls) {
                ((HttpsURLConnection) conn).disconnect(); // HttpURLConnection只能先写后读,且断开后不能复用.
                                                          // 此处取到标志位,断开conn, 后面另起一个connection.
            } else {
                ((HttpURLConnection) conn).disconnect();
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            FrameSecurity.updateTextArea("IOException captured.\n ");
            e.printStackTrace();
            System.out.println("The conn in use: "+conn);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        return exist;
    }*/

    // 头部的\r\n都是系统自己加的.
    // Content-Type 里指明了数据是以 multipart/form-data 来编码，本次请求的 boundary
    // 是什么内容。消息主体里按照字段个数又分为多个结构类似的部分，每部分都是以 --boundary 开始，
    // 紧接着是内容描述信息，然后是回车，最后是字段具体内容（文本或二进制）。有它就有分界符,没它就不需要分界符.
    // 如果传输的是文件，还要包含文件名和文件类型信息。消息主体最后以 --boundary-- 标示结束。
    // connection.setRequestMethod("POST");
    // connection.setRequestProperty("userfile2", fileName);
    public static HttpsURLConnection setHttpsConnect(HttpsURLConnection c) {
        c.setRequestProperty("User-Agent", "sunxinfeng");
        c.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        c.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
        c.setRequestProperty("Accept-Encoding", "gzip, deflate");
        c.setRequestProperty("Connection", "Keep-Alive");
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
        c.setConnectTimeout(5000); // timeout
        c.setReadTimeout(5000);
//      c.setChunkedStreamingMode(2048);//设置了ChunkedStreamingMode后，不再等待OutputStream关闭后生成完整的httprequest一次过发送，而是先发送httprequest头.
//      c.setFixedLengthStreamingMode(2048); //不能用定长的。 若定长，而实际的数据没这么长，会报insufficient data written
        return c;
    }
    public static HttpURLConnection setHttpConnect(HttpURLConnection c) {
        c.setRequestProperty("User-Agent", "sunxinfeng");
        c.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        c.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
        c.setRequestProperty("Accept-Encoding", "gzip, deflate");
        c.setRequestProperty("Connection", "Keep-Alive");
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
        c.setConnectTimeout(3000); // timeout
        c.setReadTimeout(3000);
        return c;
    }
  
}

		class MyTrust implements X509TrustManager{
		    public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
		    public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
		    public X509Certificate[] getAcceptedIssuers() {return null; }   
		}

