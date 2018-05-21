package security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class CheckPwExistOrNot /*implements Runnable*/{
    
    private String pwExistAlready = "Confirm new password:"; //静态查询是否存在密码，只用一次。动态反馈密码是否设成功用 pwSet
    public boolean pwExist = false;      //密码已设置
    private URL url;
    
    CheckPwExistOrNot(URL url){
        this.url = url;
    }

    /**
     * 检查密码是否已存在。之所以不把结果写到一个全局变量而是用返回值，是为了在多线程下载SPRF文件时，防止多个线程同时访问pwExist这一变量导致运行异常。
     */
    public boolean checkPasswordExistOrNot(/*boolean downloadSPRFinMultiThread*/) {
        boolean exist = false;
        boolean tlsStatus = FrameSecurity.tls;
        String[] seg;
        URLConnection conn = null;
        try {
            String str = null;
            SSLContext sc;
            if (tlsStatus) {
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
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            while ((str = in.readLine()) != null) {
                if (str.indexOf(pwExistAlready) > -1) { // 一检测到相关字符串,就认为密码已经存在.
                    seg = url.toString().split("[/]");
//                    if (seg[3].indexOf("connection") > -1) {
//                        FrameSecurity.updateTextArea("DIGSI conn pw exists in EN100." + seg[2] + "\n");
//                    }
                    if (seg[3].indexOf("maintenance") > -1) {
                        FrameSecurity.updateTextArea("Maintenance pw exists in EN100." + seg[2] + "\n");
                    }
                    exist = true;
                    break;
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            FrameSecurity.updateTextArea("IOException captured.\n");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } finally {
            if (tlsStatus) {
                ((HttpsURLConnection) conn).disconnect(); // HttpURLConnection只能先写后读,且断开后不能复用.
            } else {
                ((HttpURLConnection) conn).disconnect();
            }
        }
        return exist;
    }
    
}
