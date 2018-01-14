package security;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class ResetPassword {
    
    public static String fileName;

    public static void download(/* String[] args */) {

        try {
            Common.ip_seg = FrameSecurity.ip.split("[/]");
            Common.url = new URL(
                    Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2] + "/setmaintenancepassword");
            Common.checkPasswordExistOrNot(Common.url);
            if (!Common.pwExist) {
                FrameSecurity.updateTextArea("Maintenance password is not set.\n");
            } else {
                Common.url = new URL(Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2]
                        + "/downloadpasswordresetfile");
                Common.setConnection(Common.url);

                Common.connection.setDoInput(true);
                Common.connection.setDoOutput(true);

                Common.out = new BufferedOutputStream(Common.connection.getOutputStream());

                StringBuffer get = new StringBuffer();
                get.append("--" + Common.boundary + "\r\n")
                        .append("Content-Disposition: form-data; name=\"curr_password\"\r\n\r\n")
                        .append(FrameSecurity.mntpw).append("\r\n--" + Common.boundary + "--\r\n");

                Common.out.write(get.toString().getBytes());
                Common.out.flush();

                /*InputStream in = Common.connection.getInputStream();
                FileOutputStream fos = new FileOutputStream(new File("downloaded.txt"));
                byte[] buf = new byte[512];
                while (true) {
                    int len = in.read(buf);
                    if (len == -1) {
                        break;
                    }
                    fos.write(buf, 0, len);
                }*/
                String str;
                Map<String, List<String>> headerFields = Common.connection.getHeaderFields();
                System.out.println(headerFields);
                System.out.println("----"+Common.connection.getContent());
                str = headerFields.get("Content-Disposition").get(0);
                fileName = str.substring(str.indexOf("EN100"), str.length() - 1);
                str = headerFields.get("Content-Type").get(0);
                System.out.println(str);
                int length = Integer.parseInt(str.substring(str.length() - 3));
                byte[] out = new byte[length];

                DataInputStream dis = new DataInputStream(Common.connection.getInputStream());
                dis.read(out);
                String tar = FrameSecurity.prfDirectory + fileName;
                FileOutputStream fos = new FileOutputStream(tar);
                fos.write(out);
                fos.flush();
                fos.close();
                dis.close();

                FrameSecurity.updateTextArea("Download file: " + tar + ". \nLength: " + length + "\n");
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static void upload(/*String[] args*/) {
        boolean result = false;
        try {
            Common.ip_seg = FrameSecurity.ip.split("[/]");
            Common.url = new URL(
                    Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2] + "/setmaintenancepassword");
            Common.checkPasswordExistOrNot(Common.url);
            if(!Common.pwExist) {
                FrameSecurity.updateTextArea("Maintenance password is not set.\n");
            }
            Common.url = new URL(Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2] + "/resetpasswords");
            Common.setConnection(Common.url);
            
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

//            DataInputStream dis = new DataInputStream(Common.connection.getInputStream());
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
                FrameSecurity.updateTextArea("Operation fails.\n");
            }
        }
    }
    
    public static void resetDigPw() {
        boolean result = false;
        try {
            Common.ip_seg = FrameSecurity.ip.split("[/]");
            Common.url = new URL(
                    Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2] + "/setmaintenancepassword");
            Common.checkPasswordExistOrNot(Common.url);
            if (!Common.pwExist) {
                FrameSecurity.updateTextArea("Maintenance password is not set.\n");
            } // 不写else，来反向检查EN100的反应：在没设Mnt PW 时是否能进行其它操作。
            Common.url = new URL(
                    Common.ip_seg[0] + "/" + Common.ip_seg[1] + "/" + Common.ip_seg[2] + "/resetconnectionpassword");
            Common.setConnection(Common.url);

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

            // DataInputStream dis = new DataInputStream(Common.connection.getInputStream());
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

            Common.in.close();

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (!result) {
                FrameSecurity.updateTextArea("Operation fails.\n");
            }
        }
    }
    
}