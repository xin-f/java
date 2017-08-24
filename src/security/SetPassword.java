package security;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Formatter;
import java.util.Timer;
import java.util.TimerTask;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class SetPassword {
	static BufferedReader in = null;
	static int succ = 0;
	private static int timeout;
	private static String curpw;
	private static String newpw;
	private static String pwNotSet = "Confirm password:";//只有密码没设，网页里才有此字符串
	private static String pwSet = "The password has been set or changed";
	private static String boundary = null;
	private static int numFinished; //已运行次数。

	private static URL url = null;
	private static URLConnection conn = null;
	private static URLConnection connection = null;
	private static SSLContext sc = null;
	
	public static File file = null;
//	private static FileOutputStream fos = null;
	public static BufferedWriter bw = null; //保存尝试过的密码。要在点Reset后写入，所以要public.
	private static Formatter fmt = null;
	public static boolean streamClosed;
	public static boolean end;

	static PrintWriter out = null;
	private static boolean setPwSucc; //本次设密码成功
	private static boolean setPwSucc_LastTime; //上次设密码成功，用于判断否定测试时，本次要不要取上次的密码作为当前密码。如果上次设置失败，则不取，当前密码保持上上次的。
	private static boolean pwExist;		//密码已设置
	private static boolean pwInitInternal;	//密码是否由本程序初始化
	private static boolean pwInitOut_BeChangedAtLeastOnceByThisProgram;
	public static Timer t = null;//Make the timer be public so that the pw setting process can be terminated by 'Reset' in Frame.java by t.cancel()

//	public static void main(String[] s) {
	public static void set() {
		numFinished = 0;
		pwInitInternal = false; // 默认假设密码不是由本程序初始化的.->用于判断在改密码时,旧密码的来源.
								// 最外层if-else-语句,else部分要衔接一个来自if语句的变量 newpw
		pwInitOut_BeChangedAtLeastOnceByThisProgram = false; // 默认密码已设,且由外部设置. 第一次修改密码时, 从外部输入一个字符串作为原密码,修改成功把此变量置true,
						// 不再接受外部字符串. 即用来区别修改密码时第一次和后面其它次老密码的来源.		
		if(Frame.save) {
			streamClosed = false;
			try {
//				System.out.println("create new bw");
				bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
		}
		timeout = Frame.period*1000;
		t = new Timer();
		SetPasswordCycically setPasswordCycically = new SetPasswordCycically();
		t.schedule(setPasswordCycically, 0, timeout);
	}

	/**
	 * 由于EN100是HTTP短连接,设密码成功后若不再次请求setpassword,EN100不能正确上送密码已设置的状态.
	 */
	static class SetPasswordCycically extends TimerTask {
		
		String str = null;
		String result = "";
		

		public void run() {
			end = false;
			if (!Frame.stop) {
				try {
					url = new URL(Frame.ip);
					setPwSucc = false;
					pwExist = true; // 默认已经设过密码

					//conn来检查密码是否已经设置。
					if(Frame.tls) {
						conn = setHttpsConnect((HttpsURLConnection) url.openConnection());
						sc = SSLContext.getInstance("TLS");
						sc.init(null, new TrustManager[] {new MyTrust()}, new java.security.SecureRandom());
						((HttpsURLConnection) conn).setSSLSocketFactory(sc.getSocketFactory());
					}else {
						conn = setHttpConnect((HttpURLConnection)url.openConnection());
					}
					boundary = "----wowothisisunique-sxf";
					
					in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
					while ((str = in.readLine()) != null) {
						if (str.indexOf(pwNotSet) > -1) { // 一检测到相关字符串,就认为密码没设过.
							pwExist = false;
							break;
						}
					}
					if(Frame.tls) {
						((HttpsURLConnection) conn).disconnect(); // HttpURLConnection只能先写后读,且断开后不能复用.
																	// 此处取到标志位,断开conn, 后面另起一个connection.						
					}else {
						((HttpURLConnection) conn).disconnect();
					}

					//connection 用来设或改密码。
					if(Frame.tls) {
						connection = setHttpsConnect((HttpsURLConnection) url.openConnection());
						sc = SSLContext.getInstance("TLS");
						sc.init(null, new TrustManager[] {new MyTrust()}, new java.security.SecureRandom());
						((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
					}else {
						connection = setHttpConnect((HttpURLConnection) url.openConnection());
					}
					
					connection.setDoInput(true);
					connection.setDoOutput(true);
//					connection.setConnectTimeout(5000);
					if (!pwExist) {
						// System.out.println("in if");
						StringBuffer set = new StringBuffer();
						// newpw = Random.getRandomString();
						newpw = Frame.commonpw; // 第一次设密码，用输入框里的。
						if(Frame.negative)
							if(!Random.judge(newpw)) {
								newpw = "1!qQ1234";
								Frame.updateTextArea("The preset password doesn't conform to rules.\n\"1!qQ1234\" is used instead.\n");
							}
						set.append(boundary + "\r\n")
								.append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n").append(newpw)
								.append("\r\n" + boundary + "--\r\n")
								.append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n").append(newpw)
								.append("\r\n" + boundary + "--\r\n");
						out = new PrintWriter(connection.getOutputStream());
						out.write(set.toString());
						out.flush();
						
						in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
						while ((str = in.readLine()) != null) {
							result += (str + "\n");
//							System.out.println(str);
							if (str.indexOf(pwSet) != -1) {
								succ += 1;
								setPwSucc = true;
								setPwSucc_LastTime = true;
								pwInitInternal = true;
								Frame.updateTextArea("Password has been initialized.\n");
							}
						}
					}
					

					else {
						if (pwInitInternal) {
							if(setPwSucc_LastTime) { //上次即初始化那次，当然是成功的。这句不写也行。
								curpw = newpw;
								setPwSucc_LastTime = false;
							}								
						}							
						else {
							if (!pwInitOut_BeChangedAtLeastOnceByThisProgram) {//密码没被本程序改过，即这是第一次改密码，要从外部获得当前密码。
								curpw = Frame.commonpw;
								if(Frame.negative)
									if(!Random.judge(curpw)) { //起码让第一次能跑起来。
										curpw = "1!qQ1234";
										Frame.updateTextArea("The preset password doesn't conform to rules.\n\"1!qQ1234\" is used instead.\n");
									}
							} else {
								if(setPwSucc_LastTime) {
									curpw = newpw; //已经由本程序改过一次密码，所以不从外部取当前密码,而是在上次修改成功的前提下取上次的密码。
									setPwSucc_LastTime = false;
								}
								
							}								
						}
						StringBuffer change = new StringBuffer();
						if (Frame.negative)
							newpw = Random.getRandomString();
						else
							newpw = Random.getValidRandomString();
						change.append(boundary + "\r\n")
								.append("Content-Disposition: form-data; name=\"curr_password\"\r\n\r\n").append(curpw)
								.append("\r\n" + boundary + "--\r\n")
								.append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n").append(newpw)
								.append("\r\n" + boundary + "--\r\n")
								.append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n").append(newpw)

								.append("\r\n" + boundary + "--\r\n");

						out = new PrintWriter(connection.getOutputStream());
						// PrintWriter out_save = new PrintWriter(new
						// FileWriter(file));
						// BufferedWriter bw = new BufferedWriter( new
						// FileWriter(file)); //文件类最好用PrintWriter.
						out.write(change.toString());
						out.flush();
						
						in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
						while ((str = in.readLine()) != null) {
							result += (str + "\n");
							if (str.indexOf(pwSet) != -1) {
								// System.out.println(str);
								succ += 1;
								setPwSucc = true;
								setPwSucc_LastTime = true;
								pwInitOut_BeChangedAtLeastOnceByThisProgram = true;
							}
						}
					}
					/*
					 * out_save.write(result); out_save.flush(); out_save.close();
					 */
					System.out.println("Password has been set successfully for " + succ + " times.");
					Frame.updateTextAreacnt(succ);
					//e.g.: abc123!@	Invalid		fail
					if(Frame.save) {
//						bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File("logs.txt"))));
						fmt = new Formatter();
						fmt.format("%-26s", newpw);
						bw.write(fmt.toString()); //手动停止时，点了Reset，输出流即关闭，然而已经由定时器起到的当前这一次操作（即最后一次），要用到这个输出流，
								//故可能会出现NPE。 
					}

					if (!setPwSucc) {
						if(!Frame.negative) {
							//密码操作失败，且密码都是合规的。
							System.out.println("Set password failed. Process terminated. Is the current pw correct?");
							Frame.updateTextArea("Set password failed. Process terminated.\nIs the current pw correct?\n");						
							t.cancel();
							if(Frame.save) {
								bw.write("Valid    "+"FAIL");
								bw.newLine();
								bw.flush();
								bw.close(); //有t.cancel()的地方需要close()
								streamClosed = true;
							}
							if(Frame.fwpwRunning) Frame.fwpwRunning = false;
							if(Frame.digpwRunning) Frame.digpwRunning = false;
						}else {
						    //密码操作失败，此时的密码字符串未必是合规的，要作判断。
							if(Random.judge(newpw)) {
								System.out.println("Set password failed. Is the current pw correct?");
								Frame.updateTextArea("Set password failed. \nIs the current pw correct?\n");	
//								t.cancel(); //反向测试时不停止loop。
								if(Frame.save) {
									bw.write("Valid    "+"FAIL");
									bw.newLine();
									bw.flush();
//									bw.close(); //有t.cancel()的地方需要close()
//									streamClosed = true;
								}
//								if(Frame.fwpwRunning) Frame.fwpwRunning = false;
//								if(Frame.digpwRunning) Frame.digpwRunning = false;
							}else {
								System.out.println("Invalid password is rejected by EN100.");
								Frame.updateTextArea("Invalid password is rejected by EN100.\n");
								if(Frame.save) {
									bw.write("Invld    "/*+"PASS"*/);
									bw.newLine();
									bw.flush();
								}
							}
						}
												
					}else {//密码操作成功						
						if(Frame.negative) {
							//密码操作成功，密码字串可能是有效也可能是无效的。
							if(!Random.judge(newpw)) {
								//密码操作成功但密码不合规
								System.out.println("Invalid password is accepted by EN100!!!!");
								Frame.updateTextArea("Invalid password is accepted by EN100!!!!\n");	
//								t.cancel();
								if(Frame.save) {
									bw.write("Invld    "+"FAIL");
									bw.newLine();
									bw.flush();
//									bw.close(); //有t.cancel()的地方需要close()
//									streamClosed = true;
								}
//								if(Frame.fwpwRunning) Frame.fwpwRunning = false;
//								if(Frame.digpwRunning) Frame.digpwRunning = false;
							}else {
								//密码操作成功,密码合规
								if(Frame.save) {
									bw.newLine();
									bw.flush();
								}
							}
						}else {
							//密码操作成功，密码串都是有效的。
							if(Frame.save) {
								bw.newLine();
								bw.flush();
							}
						}						
					}
					numFinished++;
					if((Frame.ubound != 0)&& (numFinished == Frame.ubound)) {
						if((Frame.negative && Frame.checkUbound())	//反向测试，且checkUbound()标志置为true
							|| !Frame.negative)	
							if(t != null) t.cancel();
					}
					in.close();
					out.close();
				} catch (MalformedURLException e) {
					// new URL()
					e.printStackTrace();
				} catch (IOException e) {
					Frame.updateTextArea(
							"Connection not established.\nIf the IP is correct, try again or check it via browser.\n ");
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// SSLContext.getInstance()
					e.printStackTrace();
				} catch (KeyManagementException e) {
					e.printStackTrace();
				}
			} else
				t.cancel();
			end = true; 
		}
		
/*		private String getTime(long million) {
			int time = (int) (million - 17396*24*3600*1000);
			StringBuilder sb = new StringBuilder();
			int hour = time / 3600000;
			int min = (time - hour * 3600000)/60000;
			int sec = (time - hour * 3600000 - min * 60000)/1000;
			String mill = Long.toString(million);
			String ms = mill.substring(10,mill.length());
			sb.append(hour)
			.append(":")
			.append(min)
			.append(":")
			.append(sec)
			.append(":")
			.append(ms);
			return sb.toString();
		}*/

		private HttpsURLConnection setHttpsConnect(HttpsURLConnection c) {
			c.setRequestProperty("User-Agent", "sxf");
			c.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
			c.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
			c.setRequestProperty("Accept-Encoding", "gzip, deflate");
			c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
			c.setConnectTimeout(timeout); // timeout
			c.setReadTimeout(timeout);
			return c;
		}
		private HttpURLConnection setHttpConnect(HttpURLConnection c) {
			c.setRequestProperty("User-Agent", "sxf");
			c.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
			c.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
			c.setRequestProperty("Accept-Encoding", "gzip, deflate");
			c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
			c.setConnectTimeout(timeout); // timeout
			c.setReadTimeout(timeout);
			return c;
		}		
	}
}