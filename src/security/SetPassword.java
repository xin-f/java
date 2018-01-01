package security;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.Timer;
import java.util.TimerTask;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class SetPassword {
    
    public static int succ = 0;
    private static int attempt;
    private static int timeout;
    private static String curpw;
    private static String newpw;
    private static String pwSet = "The password has been set or changed";
    private static int numFinished; //已运行次数。

    public static URL url = null; //change to public, to be used in HttpPost. 用来查一下是否有密码。
    public static String target_password;
    
    public static File file = null;
    public static BufferedWriter bw = null; //保存尝试过的密码。要在点Reset后写入，所以要public.
    private static Formatter fmt = null;
    public static boolean streamClosed;
    public static boolean end;

    private static boolean setPwSucc; //本次设密码成功
    private static boolean setPwSucc_LastTime; //上次设密码成功，用于判断否定测试时，本次要不要取上次的密码作为当前密码。如果上次设置失败，则不取，当前密码保持上上次的。
  
    private static boolean pwInitInternal;  //密码是否由本程序初始化
    private static boolean AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram;
    public static Timer t = null;//Make the timer be public so that the pw setting process can be terminated by 'Reset' in Frame.java by t.cancel()
    public static boolean t_running;
    public static boolean self = true; //为真时，改自己对应的密码（比如点的是DigPW，就改digsi 密码)；为假时，改另一个密码(点的是DigPW，改fw 密码)。
            //为真时才需要把新密码赋给当前密码，然后再获得一个新密码。为假时，用不变的当前密码和新密码改另个网址下的密码。即一套密码用两次。

//  public static void main(String[] s) {
    public static void set() {
        numFinished = 0;
        pwInitInternal = false; // 默认假设密码不是由本程序初始化的.->用于判断在改密码时,旧密码的来源.
                                // 最外层if-else-语句,else部分要衔接一个来自if语句的变量 newpw
//      pwExist = false; //使能attack时，在prepare函数里认为pwExist为true,但到了这里又被改了，逻辑不对。把这句移到reset()里。
        attempt = 0;    //攻击尝试次数。
        AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram = false; //用来区别是否是一台有密码的现成的装置(即没走initialize的数据流)。       
        if(FrameSecurity.save) {
            streamClosed = false;
            try {
                bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        timeout = (FrameSecurity.period == 0) ? Integer.MAX_VALUE : FrameSecurity.period*100; //schedule()第三个参数要为正。
        t = new Timer();
        SetPasswordCycically setPasswordCycically = new SetPasswordCycically();
        t.schedule(setPasswordCycically, 0, timeout);
        
    }

    /**
     * 由于EN100是HTTP短连接,设密码成功后若不再次请求setpassword,EN100不能正确上送密码已设置的状态.
     */
    static class SetPasswordCycically extends TimerTask {
        
        String str = null;
        
        public void run() {
            t_running = true;
            end = false;
            if (!FrameSecurity.stop) {
                try {
                    if(self)
                        {url = new URL(FrameSecurity.ip);}
                    else
                        {url = new URL(FrameSecurity.ip_another);}
                    setPwSucc = false;
//                  pwExist = true; 

                    if (!Common.pwExist) {
                        Common.checkPasswordExistOrNot(url);
                    }
                    //connection 用来设或改密码。
                    /*if(FrameSecurity.tls) {
                        Common.connection = Common.setHttpsConnect((HttpsURLConnection) url.openConnection());
                        Common.sc = SSLContext.getInstance("TLS");
                        Common.sc.init(null, new TrustManager[] {new MyTrust()}, new java.security.SecureRandom());
                        ((HttpsURLConnection) Common.connection).setSSLSocketFactory(Common.sc.getSocketFactory());
                    }else {
                        Common.connection = Common.setHttpConnect((HttpURLConnection) url.openConnection());
                    }*/
                    Common.setConnection(url);
                    
                    Common.connection.setDoInput(true);
                    Common.connection.setDoOutput(true);
                    if (!Common.pwExist) {
                            StringBuffer set = new StringBuffer();
                            newpw = FrameSecurity.commonpw; // 第一次设密码，用输入框里的。
                            set.append("--" + Common.boundary + "\r\n")
                                    .append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n")
                                    .append(newpw).append("\r\n--" + Common.boundary + "\r\n")
                                    .append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n")
                                    .append(newpw).append("\r\n--" + Common.boundary + "--\r\n");
                            // out = new PrintWriter(connection.getOutputStream());
                            Common.out = new BufferedOutputStream(Common.connection.getOutputStream());
                            Common.out.write(set.toString().getBytes("UTF-8"));
                            Common.out.flush();

                            Common.in = new BufferedReader(new InputStreamReader(Common.connection.getInputStream(), "UTF-8"));
                            while ((str = Common.in.readLine()) != null) {
                                if (str.indexOf(pwSet) != -1) {
                                    succ += 1;
                                    setPwSucc = true;
                                    setPwSucc_LastTime = true;
                                    pwInitInternal = true;
                                    Common.pwExist = true;
                                    FrameSecurity.updateTextArea("Password has been initialized.\n");
                                }
                            }
                            if (!setPwSucc) {
                                FrameSecurity.updateTextArea("Initialize password fails. Please doublecheck!\n");
                                t.cancel();
                                t_running = false;
                            }
                    }//end of (!pwExist)                    

                    else {
                        if (pwInitInternal) {
                            if (setPwSucc_LastTime) { // 上次即初始化那次，当然是成功的。判断条件不加也行。
                                if (self) {
                                    curpw = newpw;
                                    setPwSucc_LastTime = false;
                                }
                            }
                            pwInitInternal = false; // pwInitInternal只能有一次，进来一次后就要变成false 8/25
                        } else {
                            if (setPwSucc_LastTime) {
                                if (self) {
                                    curpw = newpw; // 已经由本程序改过一次密码，所以不从外部取当前密码,而是在上次修改成功的前提下取上次的密码。
                                    setPwSucc_LastTime = false;
                                }
                            } else {
                                if (!AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram) {
                                    curpw = FrameSecurity.commonpw;
                                    if (FrameSecurity.attack) {//9.4.2017 把attack加进来时，新加的逻辑。即使不加判断条件，newpw这里被赋值后，在if(self)还会改成所需要的值。
                                        newpw = Random.getValidRandomString();
                                    }
                                } else { // 9.4.2017 把attack加进来时，新加的逻辑。
                                    if (FrameSecurity.attack) {
                                        curpw = newpw;
                                        newpw = Random.getValidRandomString();
                                    }
                                }
                            }
                        }
                        StringBuffer change = new StringBuffer();
                        if (self) {
                            if (!FrameSecurity.attack) {
                                if (FrameSecurity.negative) {
                                    newpw = Random.getRandomString();
                                } else {
                                    if (!FrameSecurity.traverse) {
                                        if (FrameSecurity.ChangePw) {
                                            newpw = target_password; //另一个密码框的字符串作为新密码来修改一次。
                                            t.cancel(); //改一次就停
                                        } else {
                                            newpw = Random.getValidRandomString();
                                        }
                                    } else {
                                        // 如果字符类型全选，根据prepare_traverse()函数给变量Charset的赋值顺序，traverse_最后赋的，所以此时traversea,traverseA,traverse0
                                        // 都为false。等traverse_类的即符号类的遍历完，通过setSelected(false)把这一类复选框取消选择。在本程序后面再进行prepare_traverse()判断。
                                        if (FrameSecurity.charset == FrameSecurity.Charset.dig) {
                                            FrameSecurity
                                                    .updateTextArea(Random.dig.substring(numFinished, numFinished + 1));
                                            System.out.print(Random.dig.substring(numFinished, numFinished + 1));
                                            newpw = Random.dig.charAt(numFinished)
                                                    + Random.getValidRandomString_traverse();
                                            if (numFinished == Random.dig.length() - 1) {
                                                FrameSecurity.chkbx0.setSelected(false);
                                            }
                                        } else if (FrameSecurity.charset == FrameSecurity.Charset.upp) {
                                            FrameSecurity
                                                    .updateTextArea(Random.upp.substring(numFinished, numFinished + 1));
                                            System.out.print(Random.upp.substring(numFinished, numFinished + 1));
                                            newpw = Random.upp.charAt(numFinished)
                                                    + Random.getValidRandomString_traverse();
                                            if (numFinished == 25) {
                                                FrameSecurity.chkbxA.setSelected(false);
                                            }
                                        } else if (FrameSecurity.charset == FrameSecurity.Charset.low) {
                                            FrameSecurity
                                                    .updateTextArea(Random.low.substring(numFinished, numFinished + 1));
                                            System.out.print(Random.low.substring(numFinished, numFinished + 1));
                                            newpw = Random.low.charAt(numFinished)
                                                    + Random.getValidRandomString_traverse();
                                            if (numFinished == 25) {
                                                FrameSecurity.chkbxa.setSelected(false);
                                            }
                                        } else if (FrameSecurity.charset == FrameSecurity.Charset.cha) {
                                            FrameSecurity
                                                    .updateTextArea(Random.cha.substring(numFinished, numFinished + 1));
                                            System.out.print(Random.cha.substring(numFinished, numFinished + 1));
                                            newpw = Random.cha.charAt(numFinished)
                                                    + Random.getValidRandomString_traverse();
                                            if (numFinished == Random.cha.length() - 1) {
                                                FrameSecurity.chkbx_.setSelected(false);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        change.append("--" + Common.boundary + "\r\n")
                                .append("Content-Disposition: form-data; name=\"curr_password\"\r\n\r\n").append(curpw)
                                .append("\r\n--" + Common.boundary + "\r\n")
                                .append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n").append(newpw)
                                .append("\r\n--" + Common.boundary + "\r\n")
                                .append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n").append(newpw)
                                .append("\r\n--" + Common.boundary + "--\r\n");

                        // out = new PrintWriter(connection.getOutputStream());
                        Common.out = new BufferedOutputStream(Common.connection.getOutputStream());
                        Common.out.write(change.toString().getBytes("UTF-8"));
                        Common.out.flush();

                        AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram = true;

                        Common.in = new BufferedReader(new InputStreamReader(Common.connection.getInputStream(), "UTF-8"));
                        while ((str = Common.in.readLine()) != null) {
                            // result += (str + "\n"); //长期运行会导致'OutOfMemoryError: Java heap space',
                            // 因为'result'没被设为 ""，每次循环都会累加。
                            if (str.indexOf(pwSet) != -1) {
                                // System.out.println(str);
                                succ += 1;
                                setPwSucc = true;
                                setPwSucc_LastTime = true;
                                if (FrameSecurity.ChangePw) {
                                    FrameSecurity.updateTextArea("Password changed to: "+ target_password);
                                }
                            }
                        }
                    }//end of pwExist

                    if (FrameSecurity.attack) {
                        attempt++;
                        FrameSecurity.updateTextAreacnt(attempt);
                    } else {
                        System.out.println("Password has been set successfully for " + succ + " times.");
                        FrameSecurity.updateTextAreacnt(succ);
                    }
                    //e.g.: abc123!@    Invalid     fail
                    if(FrameSecurity.save) {
//                      bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File("logs.txt"))));
                        fmt = new Formatter();
                        fmt.format("%-32s", newpw);
                        bw.write(fmt.toString()); //手动停止时，点了Reset，输出流即关闭，然而已经由定时器起到的当前这一次操作（即最后一次），要用到这个输出流，
                                //故可能会出现NPE。 
                    }

                    if (!setPwSucc) {
                        if (!FrameSecurity.attack) {
                            if (!FrameSecurity.negative) {
                                // 密码操作失败，且密码都是合规的。
                                System.out
                                        .println("Set password failed. Process terminated. Is the current pw correct?");
                                FrameSecurity.updateTextArea(
                                        "Set password failed. Process terminated.\nIs the current pw correct?\n");
                                t.cancel();
                                if (FrameSecurity.save) {
                                    bw.write("Valid    " + "FAIL");
                                    bw.newLine();
                                    bw.flush();
                                    bw.close(); // 有t.cancel()的地方需要close()
                                    streamClosed = true;
                                }
                                if (FrameSecurity.fwpwRunning)
                                    FrameSecurity.fwpwRunning = false;
                                if (FrameSecurity.digpwRunning)
                                    FrameSecurity.digpwRunning = false;
                            } else {
                                // 密码操作失败，此时的密码字符串未必是合规的，要作判断。
                                if (Random.judge(newpw)) {
                                    System.out.println("Set password failed. Is the current pw correct?");
                                    FrameSecurity.updateTextArea("Set password failed. \nIs the current pw correct?\n");
                                    t.cancel(); // 反向测试在密码有效却修改失败时停loop。
                                    if (FrameSecurity.save) {
                                        bw.write("Valid    " + "FAIL");
                                        bw.newLine();
                                        bw.flush();
                                        bw.close(); // 有t.cancel()的地方需要close()
                                        streamClosed = true;
                                    }
                                    // if(Frame.fwpwRunning) Frame.fwpwRunning = false;
                                    // if(Frame.digpwRunning) Frame.digpwRunning = false;
                                } else {
                                    System.out.println("Invalid password is rejected by EN100.");
                                    FrameSecurity.updateTextArea("Invalid password is rejected by EN100.\n");
                                    if (FrameSecurity.save) {
                                        bw.write("Invld    "/* +"PASS" */);
                                        bw.newLine();
                                        bw.flush();
                                    }
                                }
                            }
                        } else {
                            bw.newLine();
                            bw.flush();
                        }

                    }else {//密码操作成功                     
                        if(FrameSecurity.negative) {
                            //密码操作成功，密码字串可能是有效也可能是无效的。
                            if(!Random.judge(newpw)) {
                                //密码操作成功但密码不合规
                                System.out.println("Invalid password is accepted by EN100!!!!");
                                FrameSecurity.updateTextArea("Invalid password is accepted by EN100!!!!\n");    
//                              t.cancel();
                                if(FrameSecurity.save) {
                                    bw.write("Invld    "+"FAIL");
                                    bw.newLine();
                                    bw.flush();
//                                  bw.close(); //有t.cancel()的地方需要close()
//                                  streamClosed = true;
                                }
//                              if(Frame.fwpwRunning) Frame.fwpwRunning = false;
//                              if(Frame.digpwRunning) Frame.digpwRunning = false;
                            }else {
                                //密码操作成功,密码合规
                                if(FrameSecurity.save) {
                                    bw.newLine();
                                    bw.flush();
                                }
                            }
                        }else {
                            //密码操作成功，密码串都是有效的。
                            if(FrameSecurity.save) {
                                bw.newLine();
                                bw.flush();
                            }
                        }                       
                    }
                    if (FrameSecurity.traverse) {
                        if (!pwInitInternal)
                            numFinished++; // 遍历时初始化这次不算。若初始化也算进去，会使index从1产生字符串，则每类字符串第一个字符(空格/A/a/0)取不到了。
                    } else
                        numFinished++;
                    if (!FrameSecurity.traverse) {
                        if ((FrameSecurity.ubound != 0) && (numFinished == FrameSecurity.ubound)) {
                            if ((FrameSecurity.negative && FrameSecurity.checkUbound()) // 反向测试，且checkUbound()标志置为true
                                    || !FrameSecurity.negative) {
                                FrameSecurity.updateTextArea("The preset operation number reaches.\n");
                                if (t != null)
                                    t.cancel();
                            }
                        }
                    }else {
                        if(numFinished == FrameSecurity.ubound ){
                            FrameSecurity.updateTextArea("The preset operation number reaches.\n");
                            FrameSecurity.prepare_traverse();
                            if(FrameSecurity.traverse) {
                                //每遍历完一类字符，把该类traverse复选框的勾去掉，然后检查是不是还有其它要遍历的类。如果有，则
                                //重置numFinished，不然换到下一类字符串时不是从头开始读，而是接着上一类字符串最后一个的序号。
                                numFinished = 0; 
                            }
                            if ((t != null) && (!FrameSecurity.traverse))
                                t.cancel();
                        }
                    }
                    Common.in.close();
                    Common.out.close();

                    if(FrameSecurity.tls) { //9.2.2017
                        ((HttpsURLConnection) Common.connection).disconnect();                 
                    }else {
                        ((HttpURLConnection) Common.connection).disconnect();
                    }
                    if (FrameSecurity.alter) {
                        self = !self;
                    }
                } catch (MalformedURLException e) {
                    // new URL()
                    e.printStackTrace();
                } catch (IOException e) {
                    FrameSecurity.updateTextArea(
                            "IOException captured.\n ");
                    e.printStackTrace();
                } /*catch (NoSuchAlgorithmException e) {
                    // SSLContext.getInstance()
                    e.printStackTrace();
                } catch (KeyManagementException e) {
                    e.printStackTrace();
                }*/
            } else
                t.cancel();
            end = true; 
        }
    }
    
}