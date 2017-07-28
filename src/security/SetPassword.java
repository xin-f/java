package security;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Timer;
import java.util.TimerTask;

public class SetPassword {
	static BufferedReader in = null;
	static int succ = 0;
	private static int timeout;
	private static String curpw;
	private static String newpw;
	private static String pwNotSet = "Confirm password:";
	private static String pwSet = "The password has been set or changed";
	private static String boundary = null;
	private static String host = Frame.ip;

	static URL url = null;
	static URLConnection connection = null;

	static PrintWriter out = null;
	static boolean setPwSucc;
	static boolean pwExist;		//密码已设置
	static boolean pwInitInternal;	//密码是否由本程序初始化
	static boolean pwInitOut_BeChangedAtLeastOnce;
	public static Timer t = null;//Make the timer be public so that the pw setting process can be terminated by 'Reset' in Frame.java by t.cancel()

//	public static void main(String[] s) {
	public static void set() {
		pwInitInternal = false; // 默认假设密码不是由本程序初始化的.->用于判断在改密码时,旧密码的来源.
								// 最外层if-else-语句,else部分要衔接一个来自if语句的变量 newpw
		pwInitOut_BeChangedAtLeastOnce = false; // 默认密码已设,且由外部设置.第一次修改密码时, 从外部输入一个字符串作为原密码,修改成功把此变量置true,
						// 不再接受外部字符串. 即用来区别修改密码时第一次和后面其它次老密码的来源.
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
			try {
//				url = new URL("http://172.20.1.24/setpassword");
				url = new URL("http://"+host+"/setpassword");
				setPwSucc = false;
				pwExist = true; // 默认已经设过密码
				
				HttpURLConnection conn = setConnect((HttpURLConnection) url.openConnection());
				boundary = "---------------------wowothisisunique-sxf";

				// 加入有没有密码的判断
				in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
				while ((str = in.readLine()) != null) {
					if (str.indexOf(pwNotSet) > -1) { // 一检测到相关字符串,就认为密码没设过.
						pwExist = false;
						break;
					}
				}
				conn.disconnect(); // HttpURLConnection只能先写后读,且断开后不能复用.
									// 此处取到标志位,断开conn, 后面另起一个connection.

				HttpURLConnection connection = setConnect((HttpURLConnection) url.openConnection());
				connection.setDoInput(true);
				connection.setDoOutput(true);
				if (!pwExist) {
//					System.out.println("in if");
					StringBuffer set = new StringBuffer();
					newpw = Random.getRandomString();
					set.append(boundary + "\r\n")
							.append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n")
							.append(newpw)
							.append("\r\n" + boundary + "--\r\n")
							.append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n")
							.append(newpw)
							.append("\r\n" + boundary + "--\r\n");
					out = new PrintWriter(connection.getOutputStream());
					out.write(set.toString());
					out.flush();
					in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
					while ((str = in.readLine()) != null) {
						result += (str + "\n");
						if (str.indexOf(pwSet) != -1) {
//							System.out.println(str);
							succ += 1;
							setPwSucc = true;
							pwInitInternal = true;
						}
					}
				}

				else {
//					System.out.println("in else");
					if(pwInitInternal) curpw = newpw;
					else {
						if (!pwInitOut_BeChangedAtLeastOnce) { 
							curpw = Frame.curpw;
						} else
							curpw = newpw;
					}
					StringBuffer change = new StringBuffer();
					newpw = Random.getRandomString();
					change.append(boundary + "\r\n")
							.append("Content-Disposition: form-data; name=\"curr_password\"\r\n\r\n")
							.append(curpw)
							.append("\r\n" + boundary + "--\r\n")
							.append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n")
							.append(newpw)
							.append("\r\n" + boundary + "--\r\n")
							.append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n")
							.append(newpw)

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
							pwInitOut_BeChangedAtLeastOnce = true;
						}
					}
				}
				/*
				 * out_save.write(result); out_save.flush(); out_save.close();
				 */
				System.out.println("Password has been set successfully for " + succ+" times.");				
				Frame.updateTextAreacnt(succ);
				if (!setPwSucc) {
					System.out.println("Set password failed. Process terminated.");
					Frame.updateTextArea("Set password failed. Process terminated.\n");
//					System.exit(0);
					t.cancel();
				}
			} catch (MalformedURLException e) {
				// new URL()
				e.printStackTrace();
			} catch (IOException e) {
				// url.openConnection()
				e.printStackTrace();
			}
		}

		private HttpURLConnection setConnect(HttpURLConnection c) {
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
