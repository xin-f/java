package security;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class ManipulateTCPDTLS {
    private static int ctlVal;
    private static String setOn;
    private static String setOff;
    private static String name;
    
    public static void act(String protocol, String link, int value) {
//        ctlVal = FrameSecurity.ctlVal_DTLS;
        ctlVal = value;
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
            Common.ip_seg = FrameSecurity.ip.split("[/]");
            Common.url = new URL(
                    Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2] + "/setmaintenancepassword");
            Common.checkPasswordExistOrNot(Common.url);
            Common.url = new URL(Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2] + link);
            if (FrameSecurity.tls) {
                Common.connection = Common.setHttpsConnect((HttpsURLConnection) Common.url.openConnection());
                Common.sc = SSLContext.getInstance("TLS");
                Common.sc.init(null, new TrustManager[] { new MyTrust() }, new java.security.SecureRandom());
                ((HttpsURLConnection) Common.connection).setSSLSocketFactory(Common.sc.getSocketFactory());
            } else {
                Common.connection = Common.setHttpConnect((HttpURLConnection) Common.url.openConnection());
            }
            String newLine = "\r\n";
            Common.connection.setDoInput(true);
            Common.connection.setDoOutput(true);

            Common.out = new BufferedOutputStream(Common.connection.getOutputStream());

            StringBuffer sb_start = new StringBuffer();
            sb_start.append("--").append(Common.boundary).append(newLine);
            Common.out.write(sb_start.toString().getBytes());
            Common.out.flush();

            StringBuffer sb_ctlVal = new StringBuffer();
            sb_ctlVal.append("Content-Disposition: form-data; name=\"" + name + "\"").append(newLine).append(newLine)
                    .append(ctlVal).append(newLine).append("--").append(Common.boundary).append(newLine);
            Common.out.write(sb_ctlVal.toString().getBytes());
            Common.out.flush();

            if (Common.pwExist) {
                StringBuffer sb_pw = new StringBuffer();
                sb_pw.append("Content-Disposition: form-data; name=\"curr_password\"").append(newLine).append(newLine)
                        .append(FrameSecurity.mntpw);
                Common.out.write(sb_pw.toString().getBytes("UTF-8"));
                Common.out.flush();
            }
            StringBuffer sb_end = new StringBuffer();
            sb_end.append(newLine).append("--").append(Common.boundary).append("--").append(newLine);
            Common.out.write(sb_end.toString().getBytes());
            Common.out.flush();
            Common.out.close();

            String str;
            Common.in = new BufferedReader(new InputStreamReader(Common.connection.getInputStream()));
            while ((str = Common.in.readLine()) != null) {
                if (str.indexOf(setOn) > -1) {
                    FrameSecurity.updateTextArea(setOn + "\n");
                    break;
                }
                if (str.indexOf(setOff) > -1) {
                    FrameSecurity.updateTextArea(setOff + "\n");
                    break;
                }
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
                Common.in.close();
                if(FrameSecurity.tls) {
                    ((HttpsURLConnection) Common.connection).disconnect();
                } else {
                    ((HttpURLConnection) Common.connection).disconnect();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
/*    public static void checkCurrent(String link) {
        Common.ip_seg = FrameSecurity.ip.split("[/]");
        try {
            Common.url = new URL(Common.ip_seg[0]+"/"+Common.ip_seg[1]+"/"+Common.ip_seg[2]+"/setupsecureengineeringaccess");
            Common.setConnection(Common.url);
            String str;
            Common.in = new BufferedReader(new InputStreamReader(Common.connection.getInputStream()));
            while ((str = Common.in.readLine()) != null) {
                if (str.indexOf(isOn) > -1) {
                    FrameSecurity.updateTextArea(setOn + "\n");
                }
                if (str.indexOf(isOff) > -1) {
                    FrameSecurity.updateTextArea(setOff + "\n");
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
    }*/
}
