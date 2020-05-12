package security;

import java.io.BufferedOutputStream;
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

public class ManipulateTCPDTLS /*implements Runnable*/{
    private String setOn;
    private String setOff;
    private String name;
    private String protocol;
    private String link;
    private int value;
    private int ip3;
    private String[] host_seg;
    private boolean pwExist;
    private BufferedReader in;
    
    ManipulateTCPDTLS(String protocol, String link, int value, int ip3){
        this.protocol = protocol;
        this.link = link;
        this.value = value;
        this.ip3 = ip3;
    }

    /**
     * SessionID 默认是可重用的，前提是用同一个SSLContext。这里试过创建一个类变量SSLContext的实例（成员变量不行，即使是全局成员变量也不行），然后改造下
     * checkPasswordExistOrNot()，让其能接受参数传递。checkPasswordExistOrNot(SSLContext sc)，调用时把类变量传进去，因为传的只是引用，所以是同一个
     * SSLContext对象，能够实现第一次连接之后，后面的连接都是半握手。
     * @return
     */
    public boolean act() {
        SSLContext sc = null;
        URLConnection connection = null;
        BufferedOutputStream out;
        boolean result = false;
        URL url = null;
        host_seg = Common.host_seg;
        if(protocol.equals("DTLS")) {
            setOn = "Secure Engineering access is enabled";
            setOff = "Secure Engineering access is disabled";
            name = "dtlsOpt";
        }
        if(protocol.equals("TCP")) {
            setOn = "Webmonitor is enabled";
            setOff = "Webmonitor is disabled";
            name = "WebmonOpt";
        }
        try {
            host_seg = FrameSecurity.host.split("[/]");
            String[] ip = host_seg[2].split("[.]");
            if (FrameSecurity.sprfSegment) {
                url = new URL(host_seg[0] + "/" + host_seg[1] + "/" + ip[0] + "." + ip[1] + "." + ip[2]
                        + "." + ip3 + "/setmaintenancepassword");
                CheckPwExistOrNot checkPw = new CheckPwExistOrNot(url);
                pwExist = checkPw.checkPasswordExistOrNot();
                url = new URL(host_seg[0] + "/" + host_seg[1] + "/" + ip[0] + "." + ip[1] + "." + ip[2]
                        + "." + ip3 + link);
            } else {
                url = new URL(host_seg[0] + "/" + host_seg[1] + "/" + host_seg[2] + "/setmaintenancepassword");
                CheckPwExistOrNot checkPw = new CheckPwExistOrNot(url);
                pwExist = checkPw.checkPasswordExistOrNot();
                url = new URL(host_seg[0] + "/" + host_seg[1] + "/" + host_seg[2] + link);
            }
            
            if (FrameSecurity.tls) {
                connection = Common.setHttpsConnect((HttpsURLConnection) url.openConnection());
                sc = SSLContext.getInstance("TLS");
                sc.init(null, new TrustManager[] { new MyTrust() }, new java.security.SecureRandom());
                ((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
            } else {
                connection = Common.setHttpConnect((HttpURLConnection) url.openConnection());
            }
            String newLine = "\r\n";
            connection.setDoInput(true);
            connection.setDoOutput(true);

            out = new BufferedOutputStream(connection.getOutputStream());

            StringBuffer sb_start = new StringBuffer();
            sb_start.append("--").append(Common.boundary).append(newLine);
            out.write(sb_start.toString().getBytes());
            out.flush();

            StringBuffer sb_ctlVal = new StringBuffer();
            sb_ctlVal.append("Content-Disposition: form-data; name=\"" + name + "\"").append(newLine).append(newLine)
                    .append(value).append(newLine).append("--").append(Common.boundary).append(newLine);
            out.write(sb_ctlVal.toString().getBytes());
            out.flush();

            if (pwExist) {
                StringBuffer sb_pw = new StringBuffer();
                sb_pw.append("Content-Disposition: form-data; name=\"curr_password\"").append(newLine).append(newLine)
                        .append(FrameSecurity.mntpw);
                out.write(sb_pw.toString().getBytes("UTF-8"));
                out.flush();
            }
            StringBuffer sb_end = new StringBuffer();
            sb_end.append(newLine).append("--").append(Common.boundary).append("--").append(newLine);
            out.write(sb_end.toString().getBytes());
            out.flush();
            out.close();

            String str;
            in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            while ((str = in.readLine()) != null) {
//                System.out.println(str);
                if (str.indexOf(setOn) > -1) {
                    result = true;
                    FrameSecurity.updateTextArea(setOn + ". " + ip3 + "\n");
                    break;
                }
                if (str.indexOf(setOff) > -1) {
                    result = true;
                    FrameSecurity.updateTextArea(setOff + ". " + ip3 + "\n");
                    break;
                }
            }
            if(!result) {
                FrameSecurity.updateTextArea("Operation(manipulate TCP/DTLS) fails.\n");
                System.out.println("Operation(manipulate TCP/DTLS) fails.");
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } finally {
            try {
                in.close();
                if(FrameSecurity.tls) {
                    ((HttpsURLConnection) connection).disconnect();
                } else {
                    ((HttpURLConnection) connection).disconnect();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return result;
    }

}
