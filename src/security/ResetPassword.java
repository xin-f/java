package security;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class ResetPassword {
    
    public static String fileName;
    private boolean pwExist;
    private int cnt_downloadedSPRF = 0;

    public static boolean checkTcpStatus(int i) {
        boolean tcp = true;
        String[] ip = FrameSecurity.textField_ip.getText().split("[.]");
        String host = ip[0] + "." + ip[1] +"." + ip[2] + "." + i;
        Socket socket = null;
        try {
            SocketAddress socketAddress = new InetSocketAddress(InetAddress.getByName(host),80);
            socket = new Socket();
            socket.connect(socketAddress, 100);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
//            e.printStackTrace();
            System.out.println("TCP is disabled: " + i+ " "+Thread.currentThread().getName());
            tcp = false;
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return tcp;
    }

    public static void download() {
        String[] host_seg = FrameSecurity.host.split("[/]");
        String[] ip_seg = host_seg[2].split("[.]");
        ResetPassword SPRF = new ResetPassword();
        if (FrameSecurity.sprfSegment) {
        	int i = FrameSecurity.sprfEnd - Integer.parseInt(ip_seg[3])+1;
            ExecutorService pool = Executors.newFixedThreadPool(i);
            for (int j = Integer.parseInt(ip_seg[3]); j <= FrameSecurity.sprfEnd; j++) {
                System.out.println("Get SPRF from: " + j+ " "+Thread.currentThread().getName());
                pool.execute(SPRF.new DownloadSPRF(host_seg, ip_seg, j));
            }
        	pool.shutdown();
        	
        	//下面是用ThreadPoolExecutor实现。
//        	BlockingQueue<Runnable> queue = new ArrayBlockingQueue<Runnable>(i);
//        	ThreadPoolExecutor exec = new ThreadPoolExecutor(i,i,1000L,TimeUnit.MILLISECONDS, queue);
//        	for (int j = Integer.parseInt(ip_seg[3]); j <= FrameSecurity.sprfEnd; j++) {
//            	exec.execute(SPRF.new DownloadSPRF(host_seg, ip_seg, j));
//        	}
//        	exec.shutdown();
        } else {
            System.out.println("Get SPRF from " + Integer.parseInt(ip_seg[3]));
            SPRF.new DownloadSPRF(host_seg, ip_seg, Integer.parseInt(ip_seg[3])).downloadSPRF();
        }
    }
    
    class DownloadSPRF implements Runnable {

        String[] host_seg;
        String[] ip_seg;
        int ip_seg3;
        ManipulateTCPDTLS manipulateTCP;
        ManipulateTCPDTLS disableTCP;
        
        DownloadSPRF(String[] host, String[] ip, int i){
            host_seg = host;
            ip_seg = ip;
            ip_seg3 = i;
        }
        @Override
        public void run() {
            downloadSPRF();
        }
        
        public void downloadSPRF() {
            manipulateTCP = new ManipulateTCPDTLS("TCP", "/setupwebmonitoraccess", 1, ip_seg3);
            disableTCP = new ManipulateTCPDTLS("TCP", "/setupwebmonitoraccess", 0, ip_seg3);
            URLConnection connection = null;
            boolean tcp = checkTcpStatus(ip_seg3);
            boolean tlsStatus = FrameSecurity.tls;// 记下之前的状态，最后恢复。
            URL url;
            try {
                if (!tcp) {
                    if (manipulateTCP.act()) {
                        System.out.println("TCP is enabled to download. " + ip_seg3);
                    } else {
                        System.out.println("TCP is disabled. Exception occurs when try to enable it. " + ip_seg3+" "+Thread.currentThread().getName());
                    }
                }
                // 由于https不能下载，统一改成http
                /*
                 * Common.host_seg = FrameSecurity.host.split("[/]"); Common.url = new URL(
                 * Common.host_seg[0] + "/" + Common.host_seg[1] + "/" + Common.host_seg[2] +
                 * "/setmaintenancepassword"); Common.checkPasswordExistOrNot(Common.url);
                 * 
                 * if (!Common.pwExist) { FrameSecurity.
                 * updateTextArea("Maintenance password is not set. No SPRF available.\n"); }
                 * else { Common.url = new URL(Common.host_seg[0] + "/" + Common.host_seg[1] +
                 * "/" + Common.host_seg[2] + "/downloadpasswordresetfile");
                 * Common.setConnection(Common.url);
                 */
                
                Thread.sleep(100);	//强制让线程等待，否则，可能A线程读到的FrameSecurity.tls是B线程已经改过的。

                FrameSecurity.tls = false;
                
                if (tlsStatus) {
                    url = new URL(host_seg[0].substring(0, host_seg[0].length() - 2) + ":" + "/" + host_seg[1] + "/"
                            + ip_seg[0] + "." + ip_seg[1] + "." + ip_seg[2] + "." + ip_seg3
                            + "/setmaintenancepassword");
                } else {
                    url = new URL(host_seg[0] + "/" + host_seg[1] + "/" + ip_seg[0] + "." + ip_seg[1] + "." + ip_seg[2]
                            + "." + ip_seg3 + "/setmaintenancepassword");
                }

                CheckPwExistOrNot checkPw = new CheckPwExistOrNot(url);

                if (!checkPw.checkPasswordExistOrNot()) {
                    FrameSecurity.updateTextArea("Maintenance password is not set, or connection not established. No SPRF available.\n");
                } else {
                    if (tlsStatus) {
                        url = new URL(host_seg[0].substring(0, host_seg[0].length() - 2) + ":" + "/" + host_seg[1] + "/"
                                + ip_seg[0] + "." + ip_seg[1] + "." + ip_seg[2] + "." + ip_seg3
                                + "/downloadpasswordresetfile");
                    } else {
                        url = new URL(host_seg[0] + "/" + host_seg[1] + "/" + ip_seg[0] + "." + ip_seg[1] + "."
                                + ip_seg[2] + "." + ip_seg3 + "/downloadpasswordresetfile");
                    }
                    connection = Common.setHttpConnect((HttpURLConnection) url.openConnection());// 固定改成http
                    connection.setDoInput(true);
                    connection.setDoOutput(true);

                    Common.out = new BufferedOutputStream(connection.getOutputStream());

                    StringBuffer get = new StringBuffer();
                    get.append("--" + Common.boundary + "\r\n")
                            .append("Content-Disposition: form-data; name=\"curr_password\"\r\n\r\n")
                            .append(FrameSecurity.mntpw).append("\r\n--" + Common.boundary + "--\r\n");

                    Common.out.write(get.toString().getBytes());
                    Common.out.flush();

                    Thread.sleep(3000); // 必须要加，怪了。
                    String str;
                    Map<String, List<String>> headerFields = connection.getHeaderFields();
                    System.out.println(headerFields);
//                    System.out.println("----" + connection.getContent());
                    str = headerFields.get("Content-Disposition").get(0);
                    fileName = str.substring(str.indexOf("EN100"), str.length() - 1);
//                    str = headerFields.get("Content-Length").get(0);
//                    System.out.println(str);
                    int length = connection.getContentLength();
//                    int length = Integer.parseInt(str);
                    byte[] out = new byte[length];

                    DataInputStream dis = new DataInputStream(connection.getInputStream());
                    dis.read(out);
                    String tar = FrameSecurity.prfDirectory + "\\" + fileName;
                    FileOutputStream fos = new FileOutputStream(tar);
                    fos.write(out);
                    fos.flush();
                    fos.close();
                    dis.close();

                    FrameSecurity.updateTextArea("Download SPRF file finished: " + ip_seg3 + " " + tar + ". \nLength: " + length + "\n");
                    cnt_downloadedSPRF++;
                    FrameSecurity.updateTextAreacnt(cnt_downloadedSPRF);
                }
            } catch (MalformedURLException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
                FrameSecurity.updateTextArea("Download SPRF file failed.\n");
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                FrameSecurity.tls = tlsStatus;
                if (!tcp) {
                    disableTCP.act();
                }
            }
            
        }
    }
    
    public void upload(/*String[] args*/) {
        boolean result = false;
        URL url = null;
        try {
            Common.host_seg = FrameSecurity.host.split("[/]");
            url = new URL(
                    Common.host_seg[0] + "/" + Common.host_seg[1] + "/" + Common.host_seg[2] + "/setmaintenancepassword");
            CheckPwExistOrNot checkPw = new CheckPwExistOrNot(url);
            pwExist = checkPw.checkPasswordExistOrNot();
            if(!pwExist) {
                FrameSecurity.updateTextArea("Maintenance password is not set.\n");
            }
            url = new URL(Common.host_seg[0] + "/" + Common.host_seg[1] + "/" + Common.host_seg[2] + "/resetpasswords");
            Common.connection = Common.setConnection(url);
            
            Common.connection.setDoInput(true);
            Common.connection.setDoOutput(true);
            FrameSecurity.updateTextArea("RPF file: " + FrameSecurity.prfFile + "\n");
            String[] tmp= FrameSecurity.prfFile.split("[\\\\]");
            fileName = tmp[tmp.length-1];
            Common.out = new BufferedOutputStream(Common.connection.getOutputStream());
            String newLine = "\r\n";
            StringBuffer sb_start = new StringBuffer();
            sb_start.append("--").append(Common.boundary).append(newLine);
            Common.out.write(sb_start.toString().getBytes());
            Common.out.flush();
            
            StringBuffer sb_prf = new StringBuffer();
            sb_prf.append("Content-Disposition: form-data; name=\"userfile2\";filename=" + "\"" + fileName + "\"") 
                    .append(newLine).append("Content-Type: application/octet-stream").append(newLine)
                    .append(newLine);

            Common.out.write(sb_prf.toString().getBytes());
            Common.out.flush(); 

            File file = new File(FrameSecurity.prfFile);
            FileInputStream fis = new FileInputStream(file);
            byte[] bytes = new byte[512];
            int numReadByte = 0;
            while ((numReadByte = fis.read(bytes, 0, 512)) > 0) { 
                Common.out.write(bytes, 0, numReadByte);
                Common.out.flush();
            }

            StringBuffer sb_end = new StringBuffer();
            sb_end.append(newLine).append("--").append(Common.boundary).append("--").append(newLine);
            Common.out.write(sb_end.toString().getBytes());
            Common.out.flush();
            
            Common.out.close();
            fis.close();

            String str;
            Common.in = new BufferedReader(new InputStreamReader(Common.connection.getInputStream()));
            while ((str = Common.in.readLine()) != null) {
                if (str.indexOf("have been successfully reset") > -1) {
                    result = true;
                    FrameSecurity.updateTextArea("Reset passwortds successfully.\n");
                    break;
                }
                if (str.indexOf("The provided") > -1) {
                    result = false;
                    FrameSecurity.updateTextArea("Incorrect PRF file is selected.\n");
                    break;
                }
            }
            
            Common.in.close();

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            //放在finally 里判断，是因为原来放在while{}后面，在connection.getInputStream() 超时异常后，后面的代码不走了，无法得知是否操作成功。
            if(!result) {
                FrameSecurity.updateTextArea("Upload SPRF fails.\n");
            }
        }
    }
    
    public void resetDigPw() {
        boolean result = false;
        URL url = null;
        try {
            Common.host_seg = FrameSecurity.host.split("[/]");
            CheckPwExistOrNot checkPw = new CheckPwExistOrNot(new URL(
                    Common.host_seg[0] + "/" + Common.host_seg[1] + "/" + Common.host_seg[2] + "/setconnectionpassword"));
            pwExist  = checkPw.checkPasswordExistOrNot();
            if (!pwExist) {
                System.out.println("Digsi connection pw does not exist.");
                FrameSecurity.updateTextArea("Digsi conn pw does not exist.\n");
            } else {
                url = new URL(
                        Common.host_seg[0] + "/" + Common.host_seg[1] + "/" + Common.host_seg[2] + "/setmaintenancepassword");
                checkPw = new CheckPwExistOrNot(url);
                checkPw.checkPasswordExistOrNot();
                if (!pwExist) {
                    FrameSecurity.updateTextArea("Maintenance password is not set.\n");
                } // 不写else，来反向检查EN100的反应：在没设Mnt PW 时是否能进行其它操作。
                url = new URL(Common.host_seg[0] + "/" + Common.host_seg[1] + "/" + Common.host_seg[2]
                        + "/resetconnectionpassword");
                Common.connection = Common.setConnection(url);

                Common.connection.setDoInput(true);
                Common.connection.setDoOutput(true);
                Common.out = new BufferedOutputStream(Common.connection.getOutputStream());

                StringBuffer get = new StringBuffer();
                get.append("--" + Common.boundary + "\r\n")
                        .append("Content-Disposition: form-data; name=\"curr_password\"\r\n\r\n")
                        .append(FrameSecurity.mntpw).append("\r\n--" + Common.boundary + "--\r\n");

                Common.out.write(get.toString().getBytes());
                Common.out.flush();
                Common.out.close();

                String str;
                Common.in = new BufferedReader(new InputStreamReader(Common.connection.getInputStream()));
                while ((str = Common.in.readLine()) != null) {
                    if (str.indexOf("password successfully") > -1) {
                        result = true;
                        FrameSecurity.updateTextArea("Reset DIGSI password successfully.\n");
                        break;
                    }
                    if (str.indexOf("Maintenance password") > -1) {
                        result = false;
                        FrameSecurity.updateTextArea("Incorrect Maintenance password is input.\n");
                        break;
                    }
                }

                Common.in.close();}

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (!result) {
                if(pwExist)
                FrameSecurity.updateTextArea("Reset DGISI connection pw fails.\n");
            }
        }
    }
    
}