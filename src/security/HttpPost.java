package security;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class HttpPost {
//  private static BufferedReader in = null;
    private static File file = null;
    private static String fileName = null;
    private static String password = null;
    private static String boundary = "----sunxinfeng";
    public static volatile int suc;
    public static Timer t = null; //Make the timer be public so that the uploading process can be terminated by 'Reset' in Frame.java by t.cancel()
    public static  boolean t_running;
    private static boolean isCms = false;
    private static boolean noRestart;
    public static boolean is_cms_fw = false; //.pck or .cms ,for 烟台万华
    private String str_fw = null; //file path of firmware

    public static void upldFW() {  
        HttpPost httpPost = new HttpPost();
        noRestart = false;
        /*
        String str = FrameSecurity.fw.trim(); //如果最后有空格
        if(str.endsWith("-norestart")) {
            str = str.substring(0,str.indexOf("-norestart")).trim(); //如果文件名和-norestart之间有空格
            noRestart = true;
        }
        file = new File(str);
        int i;
        //取.pck的文件名，只保留最后一个反斜杠后的内容。
        while((i = str.indexOf("\\")) > -1){
            str= str.substring(i+1, str.length());
        }
        fileName = str.toLowerCase();
        if (fileName.endsWith(".cms")) isCms = true; //4.30支持pck
        */
        //password = FrameSecurity.mntpw;
//        String[] host_seg = FrameSecurity.host.split("[/]");
        Common.host_seg = FrameSecurity.host.substring(0, FrameSecurity.host.length() - 7).split("[.]"); //https://172.20.1.100 或http://172.20.1.100
        if (!FrameSecurity.fwSegment) {
            t = new Timer();
            UpldFWTask task_upldFw = httpPost.new UpldFWTask(Integer.parseInt(Common.host_seg[3]) );
            //t.schedule(task_upldFw, 1000, FrameSecurity.period*100);
            t.schedule(task_upldFw, 0);
            if(FrameSecurity.getCurrentVersion)
				try {
					FrameSecurity.fileWrite_current_version_file.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
        } else {
            FrameSecurity.updateTextArea("Upload FW to a cluster of servers.\n");
            if (Integer.parseInt(Common.host_seg[3]) > FrameSecurity.fwEnd)
                FrameSecurity.updateTextArea("The END ip value should be larger than the START one.\n");
            else {
            	int num = FrameSecurity.fwEnd - Integer.parseInt(Common.host_seg[3])+1;
            	//newFixedThreadPool用的Queue是LinkedBlockingQueue, 容量为：Integer.MAX_VALUE
                ExecutorService pool = Executors.newFixedThreadPool(num);
                for (int j = Integer.parseInt(Common.host_seg[3]); j <= FrameSecurity.fwEnd; j++) {
                    // UpldFWTask task_upldFw = httpPost.new UpldFWTask(j);
                    pool.execute(httpPost.new UpldFWTask(j ));
                }
                pool.shutdown();                
                try {
					pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
					FrameSecurity.updateTextArea("All tasks finished");
	                FrameSecurity.reset(); //群下时，自动reset。烟台万华
	                if(FrameSecurity.getCurrentVersion)
	                	FrameSecurity.fileWrite_current_version_file.close();
				} catch (InterruptedException e) {
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}                
            }
        }
   }  

    
    private boolean isTls(String host) {
        Socket socket = new Socket();
        String ip = host.split("[/]")[2];
        try {
            socket.connect(new InetSocketAddress(ip, 80), 1000);
            return false;
        } catch (IOException e) {
            //e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                //e.printStackTrace();
            }
        }
        socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(ip, 443), 1000);
            return  true;
        } catch (IOException e) {
            //e.printStackTrace();	            
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                //e.printStackTrace();
            }
        }
		//return 0;
		return false;
    }
    
    class UpldFWTask extends TimerTask {
        private int seg4;
        private boolean tls;
//        BufferedReader in = null; //不能放在这里，要放在run()里
        
     // 多线程upload时，必须在自己的类里定义连接而不能用Common里的。但放在这里也是错的！！在多线程时，这里放共享变量。显然每个线程都要有一个连接，所以要把这个变量放到run()方法里面。
//        URLConnection connection = null; 

        UpldFWTask(int i ) {
            seg4 = i;
            //this.tls = tls;
        }

        @Override
        public void run() {
        	boolean pwExist = false;
            t_running = true;
            try {
                BufferedReader in ;
                URLConnection connection = null;
                SSLContext sc;
                URL url_upload = null;//new URL(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4 + "/upload");
                //System.out.println("Server: " + url_upload.toString());
                tls = isTls(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4);               
                //if (FrameSecurity.tls) {
                if (tls) {
                    if(FrameSecurity.getCurrentVersion) {
	                	URL url = new URL(Common.host_seg[0] + "."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4 + "/modstatus");
	                    CheckPwExistOrNot checkPw = new CheckPwExistOrNot(url, true);
	                    checkPw.checkCurrentFPGAVersion();
	                    return;
                    }
                	url_upload = new URL(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4 + "/upload");
                	URL url = new URL(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4 + "/setmaintenancepassword");
                    CheckPwExistOrNot checkPw = new CheckPwExistOrNot(url, true);
                    pwExist = checkPw.checkPasswordExistOrNot();
                    is_cms_fw = checkPw.is_cms_fw();
                    connection = (HttpsURLConnection) url_upload.openConnection();
                    sc = SSLContext.getInstance("TLS");
                    sc.init(null, new TrustManager[] { new MyTrust() }, new java.security.SecureRandom());
                    ((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
                } else {

                    if(FrameSecurity.getCurrentVersion) {
	                	URL url = new URL(Common.host_seg[0].substring(0, 4)+Common.host_seg[0].substring(5) +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4 + "/modstatus");
	                    CheckPwExistOrNot checkPw = new CheckPwExistOrNot(url, false);
	                    checkPw.checkCurrentFPGAVersion();
	                    return;
                    }

                	url_upload = new URL(Common.host_seg[0].substring(0, 4)+Common.host_seg[0].substring(5) +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4 + "/upload");
                    connection = (HttpURLConnection)url_upload.openConnection();
                }

                String newLine = "\r\n";
                // 头部的\r\n都是系统自己加的.
                //connection.setRequestProperty("User-Agent", "sxf");
                //connection.setRequestProperty("Accept",
                //        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                //connection.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
                //connection.setRequestProperty("Accept-Encoding", "gzip, deflate");
                connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);

                connection.setDoInput(true);
                connection.setDoOutput(true);
                // connection.setConnectTimeout(2000);
                // connection.connect();
                
                str_fw = FrameSecurity.fw.trim(); //如果最后有空格
                if(str_fw.endsWith("-norestart")) {
                	str_fw = str_fw.substring(0,str_fw.indexOf("-norestart")).trim(); //如果文件名和-norestart之间有空格
                    noRestart = true;
                }
                //for YanTaiWanHua, remove extension name, then retrieve extension automatically according to is_cms_fw. So there must be 2 files in same folder
                //with same file name but different extension name.
                str_fw = str_fw.substring(0, str_fw.length()-3); 
                if(is_cms_fw) str_fw = str_fw + "cms";
                else str_fw = str_fw + "pck";
                file = new File(str_fw);
                int i;
                //取.pck的文件名，只保留最后一个反斜杠后的内容。
                while((i = str_fw.indexOf("\\")) > -1){
                	str_fw= str_fw.substring(i+1, str_fw.length());
                }
                fileName = str_fw.toLowerCase();
                if (fileName.endsWith(".cms")) isCms = true; //4.30支持pck

                BufferedOutputStream out = new BufferedOutputStream(connection.getOutputStream());
                //
                StringBuffer sb_start = new StringBuffer();
                sb_start
                .append("--")  
                .append(boundary)
                .append(newLine);
                out.write(sb_start.toString().getBytes());
                out.flush();
                //
                 
                StringBuffer sb_fw = new StringBuffer();
                sb_fw.append("Content-Disposition: form-data; name=\"userfile2\";filename=" + "\"" + fileName + "\"") // 注意格式,边看wireshark边凑.
                        .append(newLine).append("Content-Type: application/octet-stream").append(newLine)
                        .append(newLine);

                FileInputStream fis = new FileInputStream(file);
                byte[] bytes = new byte[1024];
                int numReadByte = 0;
                out.write(sb_fw.toString().getBytes());
                out.flush(); // flush()很关键.
                while ((numReadByte = fis.read(bytes, 0, 1024)) > 0) { // 写数据内容,即.pck
                    out.write(bytes, 0, numReadByte);
                    // 不带flush(),都是624请求FIN. 然后都会报超时,
                    out.flush();
                    // System.out.println(new String(bytes));
                }
                
                if (pwExist) {
                    StringBuffer sb_middle = new StringBuffer();
                    sb_middle.append(newLine).append("--").append(boundary).append(newLine);
                    out.write(sb_middle.toString().getBytes());
                    out.flush();
                    
                    String ip_str = Common.host_seg[0].substring(Common.host_seg[0].length()-3);
    	        	long ip = Long.parseLong(ip_str)<<24 | Long.parseLong(Common.host_seg[1])<<16 | Long.parseLong(Common.host_seg[2])<<8 | Long.parseLong(Common.host_seg[3]);
    	        	if(FrameSecurity.map_ip_pw!=null)
                        password = FrameSecurity.map_ip_pw.get(ip);
                    if(password == null)   password = FrameSecurity.mntpw;
                    StringBuffer sb_pw = new StringBuffer(); // 写边界符,约定上传属性,格式application/octet-stream
                    sb_pw/* .append(boundary).append(newLine) */.append(
                            "Content-Disposition: form-data; name=\"curr_password\"").append(newLine).append(newLine)
                            .append(password)/*
                                              * .append(newLine).append(boundary) .append(newLine)
                                              */;
                    out.write(sb_pw.toString().getBytes("UTF-8"));
                    out.flush();
                }
                StringBuffer sb_end = new StringBuffer();
                sb_end.append(newLine)
                .append("--")  //11.17.2017
                .append(boundary)
                .append("--") //11.17.2017
                .append(newLine);
                out.write(sb_end.toString().getBytes());
                out.flush();

                /*
                 * 用浏览器上传时的格式: MIME Multipart Media Encapsulation, Type: multipart/form-data,
                 * Boundary: "---------------------------177882047830227" [Type:
                 * multipart/form-data] First boundary:
                 * -----------------------------177882047830227\r\n Encapsulated multipart part:
                 * Content-Disposition: form-data; name="curr_password"\r\n\r\n Data (3 bytes)
                 * Data: 787878 [Length: 3] Boundary:
                 * \r\n-----------------------------177882047830227\r\n Encapsulated multipart
                 * part: (application/octet-stream) Content-Disposition: form-data;
                 * name="userfile2"; filename="IEC61850_81.pck"\r\n Content-Type:
                 * application/octet-stream\r\n\r\n Data (1532784 bytes) Last boundary:
                 * \r\n-----------------------------177882047830227--\r\n
                 */

                fis.close();
                out.close();
                String str;
                in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                while ((str = in.readLine()) != null) {
                    if (str.indexOf("Update in progress") > -1) {
                        suc += 1;
                        System.out.println("FW transmitting finished " + suc + " times. Wait for writing to flash.");
                        FrameSecurity.updateTextAreacnt(suc);
                        // String str1 = "FW upload successful "+suc+" time.\n";
                        // String str2 = "FW upload successful "+suc+" times.\n";
                        // str = (suc == 1)?"":"";
                        FrameSecurity.updateTextArea((suc == 1) ? "FW transmission finished " + suc + " time."+"("+ seg4 +"). Wait for writing flash...\n"
                                :"FW transmission finished " + suc + " times."+"("+ seg4 +"). Wait for writing flash...\n");
                        break;
                    }
                    if (str.indexOf("The password is incorrect!") > -1) {
                        System.out.println("FW upload failed. Pw is not correct.");
                        FrameSecurity.updateTextArea("FW upload failed. Pw is not correct."+ seg4 +"\n");
                    }
                }
                // System.out.println(connection.getHeaderField(0)); //HTTP/1.0 200 OK
                in.close();
                //return; //
                if (!FrameSecurity.fwSegment) { //烟台万华
                	System.out.println("Uploading finished");
                	FrameSecurity.reset();
                }
                
                if(false) {
                if (isCms) {
                    try {
                        Thread.sleep(1000 * 100); // 硬等100秒,检查签名，等EN100忙完了再去问，不然能问死。只用于V4.33及以上，即V4.30(pck)不用等。
                    } catch (InterruptedException e1) {
                        e1.printStackTrace();
                    }
                }
                try {
                    Thread.sleep(1000 * 100); // 再等100秒,写flash.，即下pck等100s，下cms共200s。
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
                
	            if (!noRestart) {	
	                // 设置阻塞，每5秒查询一次页面内容，直到出现"Now restart EN100 and wait 60 seconds".
	                // 再访问ip/En100Restart2自动完成重启
	                boolean write_finish = false;
	                while (!write_finish) {
	                    URL url_status = null;
	                    URL url_restart = null;
	                    try {
	                    	//if (FrameSecurity.tls) {
	                        if (tls) {
	                            url_status = new URL(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4
	                                    + "/modstatus"); // https://IP/modstatus
	                            connection = (HttpsURLConnection) url_status.openConnection();
	                            sc = SSLContext.getInstance("TLS");
	                            sc.init(null, new TrustManager[] { new MyTrust() }, new java.security.SecureRandom());
	                            ((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
	                        } else {
	                            url_status = new URL(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4
	                                    + "/modstatus"); // http://IP/modstatus
	                            connection = url_status.openConnection();
	                        }
	                        BufferedReader in_after_upload = new BufferedReader(new InputStreamReader(connection.getInputStream()));
	                        String str1 = "";
	                        //readLine()并不是读取到没有数据时就返回null(其它read方法当读到没有数据时返回-1)
	                        //readLine()是一个阻塞函数，当没有数据读取时，就一直会阻塞,在数据流发生异常或者另一端被close()掉时，才会返回null值。
	                        while ((str1 = in_after_upload.readLine()) != null) {
	                            if (str1.indexOf("Now restart EN100 and wait 60 seconds") > -1) {
	                                FrameSecurity.updateTextArea("Write flash finished, restart..."+seg4+"\n");
	                                System.out.println("Writing flash finished. Restart now. Please wait..."+ seg4);
	                                write_finish = true;
	                                if (tls) {
	                                //if (FrameSecurity.tls) {
	                                    url_restart = new URL(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4
	                                            + "/En100Restart2"); // https://IP/En100Restart2
	                                    connection = (HttpsURLConnection) url_restart.openConnection();
	                                    sc = SSLContext.getInstance("TLS");
	                                    sc.init(null, new TrustManager[] { new MyTrust() },
	                                            new java.security.SecureRandom());
	                                    ((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
	                                } else {
	                                    url_restart = new URL(Common.host_seg[0] +"."+ Common.host_seg[1] +"."+ Common.host_seg[2]+"." + seg4
	                                            + "/En100Restart2"); // http://IP/En100Restart2
	                                    connection = url_restart.openConnection();
	                                }
	                                ((HttpURLConnection) connection).getResponseCode();
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
	                    }
	                    try {
	                        Thread.sleep(5000);
	                    } catch (InterruptedException e) {
	                        e.printStackTrace();
	                    }
	                }
	            }

                // 设置阻塞，ping不能装置就等5秒，直到重启完成后再让timer继续。
                while (FrameSecurity.serverLost) {
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }}

            } catch (MalformedURLException e) {
                // new URL()
                e.printStackTrace();
            } catch (IOException e) {
                FrameSecurity.updateTextArea(
                        "Failed: "+seg4+" Try again with browser to make sure IP and firmware file " + str_fw +" are correct.\n");
                //e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
        }
    }
}


/*
成功时的log:
+++ 00001 00298355 Mo 26.06.2017 15:18:18:306 start firmware upload from client 172.020.001.001:52067
+++ 00002 00298357 Mo 26.06.2017 15:18:18:308 HTTP: Start Upload max. 3194880 Bytes
+++ 00003 00298653 Mo 26.06.2017 15:18:18:605 HTTP: file "IEC61850_81.pck"
+++ 00004 00301373 Mo 26.06.2017 15:18:21:325 Received "APPL" EN100 firmware update (1529328 bytes) from 172.020.001.001:52067 ( ).
+++ 00005 00302091 Mo 26.06.2017 15:18:22:042 HTTP: Code flashed len = 1529332
+++ 00006 00327833 Mo 26.06.2017 15:18:47:786 HTTP: Code flash OK.

超时时的log: no flush().
+++ 00007 00429859 Mo 26.06.2017 15:20:29:814 start firmware upload from client 172.020.001.001:52070
+++ 00008 00429859 Mo 26.06.2017 15:20:29:814 HTTP: Start Upload max. 3194880 Bytes
+++ 00009 00430149 Mo 26.06.2017 15:20:30:104 HTTP: file "IEC61850_81.pck"
+++ 00010 00437056 Mo 26.06.2017 15:20:37:011 upload busy for client 172.020.001.001:52070
+++ 00011 00443089 Mo 26.06.2017 15:20:43:044 upload time exceeded
end of system log
*/
