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
    
    public static String boundary = "----sunxinfeng";
    public static SSLContext sc = null;
    public String pwExistAlready = "Confirm new password:"; //静态查询是否存在密码，只用一次。动态反馈密码是否设成功用 pwSet
    public boolean pwExist;      //密码已设置
    public static BufferedReader in = null;
    public static URLConnection connection = null;
    public static BufferedOutputStream out;
    public static String[] host_seg;
    public static String isOn = "value=\"1\""; //TCP, DTLS的状态
    public static String isOff = "value=\"0\"";
    
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

