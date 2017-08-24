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
	private static String pwNotSet = "Confirm password:";//ֻ������û�裬��ҳ����д��ַ���
	private static String pwSet = "The password has been set or changed";
	private static String boundary = null;
	private static int numFinished; //�����д�����

	private static URL url = null;
	private static URLConnection conn = null;
	private static URLConnection connection = null;
	private static SSLContext sc = null;
	
	public static File file = null;
//	private static FileOutputStream fos = null;
	public static BufferedWriter bw = null; //���波�Թ������롣Ҫ�ڵ�Reset��д�룬����Ҫpublic.
	private static Formatter fmt = null;
	public static boolean streamClosed;
	public static boolean end;

	static PrintWriter out = null;
	private static boolean setPwSucc; //����������ɹ�
	private static boolean setPwSucc_LastTime; //�ϴ�������ɹ��������жϷ񶨲���ʱ������Ҫ��Ҫȡ�ϴε�������Ϊ��ǰ���롣����ϴ�����ʧ�ܣ���ȡ����ǰ���뱣�����ϴεġ�
	private static boolean pwExist;		//����������
	private static boolean pwInitInternal;	//�����Ƿ��ɱ������ʼ��
	private static boolean pwInitOut_BeChangedAtLeastOnceByThisProgram;
	public static Timer t = null;//Make the timer be public so that the pw setting process can be terminated by 'Reset' in Frame.java by t.cancel()

//	public static void main(String[] s) {
	public static void set() {
		numFinished = 0;
		pwInitInternal = false; // Ĭ�ϼ������벻���ɱ������ʼ����.->�����ж��ڸ�����ʱ,���������Դ.
								// �����if-else-���,else����Ҫ�ν�һ������if���ı��� newpw
		pwInitOut_BeChangedAtLeastOnceByThisProgram = false; // Ĭ����������,�����ⲿ����. ��һ���޸�����ʱ, ���ⲿ����һ���ַ�����Ϊԭ����,�޸ĳɹ��Ѵ˱�����true,
						// ���ٽ����ⲿ�ַ���. �����������޸�����ʱ��һ�κͺ������������������Դ.		
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
	 * ����EN100��HTTP������,������ɹ��������ٴ�����setpassword,EN100������ȷ�������������õ�״̬.
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
					pwExist = true; // Ĭ���Ѿ��������

					//conn����������Ƿ��Ѿ����á�
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
						if (str.indexOf(pwNotSet) > -1) { // һ��⵽����ַ���,����Ϊ����û���.
							pwExist = false;
							break;
						}
					}
					if(Frame.tls) {
						((HttpsURLConnection) conn).disconnect(); // HttpURLConnectionֻ����д���,�ҶϿ����ܸ���.
																	// �˴�ȡ����־λ,�Ͽ�conn, ��������һ��connection.						
					}else {
						((HttpURLConnection) conn).disconnect();
					}

					//connection �����������롣
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
						newpw = Frame.commonpw; // ��һ�������룬���������ġ�
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
							if(setPwSucc_LastTime) { //�ϴμ���ʼ���ǴΣ���Ȼ�ǳɹ��ġ���䲻дҲ�С�
								curpw = newpw;
								setPwSucc_LastTime = false;
							}								
						}							
						else {
							if (!pwInitOut_BeChangedAtLeastOnceByThisProgram) {//����û��������Ĺ��������ǵ�һ�θ����룬Ҫ���ⲿ��õ�ǰ���롣
								curpw = Frame.commonpw;
								if(Frame.negative)
									if(!Random.judge(curpw)) { //�����õ�һ������������
										curpw = "1!qQ1234";
										Frame.updateTextArea("The preset password doesn't conform to rules.\n\"1!qQ1234\" is used instead.\n");
									}
							} else {
								if(setPwSucc_LastTime) {
									curpw = newpw; //�Ѿ��ɱ�����Ĺ�һ�����룬���Բ����ⲿȡ��ǰ����,�������ϴ��޸ĳɹ���ǰ����ȡ�ϴε����롣
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
						// FileWriter(file)); //�ļ��������PrintWriter.
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
						bw.write(fmt.toString()); //�ֶ�ֹͣʱ������Reset����������رգ�Ȼ���Ѿ��ɶ�ʱ���𵽵ĵ�ǰ��һ�β����������һ�Σ���Ҫ�õ�����������
								//�ʿ��ܻ����NPE�� 
					}

					if (!setPwSucc) {
						if(!Frame.negative) {
							//�������ʧ�ܣ������붼�ǺϹ�ġ�
							System.out.println("Set password failed. Process terminated. Is the current pw correct?");
							Frame.updateTextArea("Set password failed. Process terminated.\nIs the current pw correct?\n");						
							t.cancel();
							if(Frame.save) {
								bw.write("Valid    "+"FAIL");
								bw.newLine();
								bw.flush();
								bw.close(); //��t.cancel()�ĵط���Ҫclose()
								streamClosed = true;
							}
							if(Frame.fwpwRunning) Frame.fwpwRunning = false;
							if(Frame.digpwRunning) Frame.digpwRunning = false;
						}else {
						    //�������ʧ�ܣ���ʱ�������ַ���δ���ǺϹ�ģ�Ҫ���жϡ�
							if(Random.judge(newpw)) {
								System.out.println("Set password failed. Is the current pw correct?");
								Frame.updateTextArea("Set password failed. \nIs the current pw correct?\n");	
//								t.cancel(); //�������ʱ��ֹͣloop��
								if(Frame.save) {
									bw.write("Valid    "+"FAIL");
									bw.newLine();
									bw.flush();
//									bw.close(); //��t.cancel()�ĵط���Ҫclose()
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
												
					}else {//��������ɹ�						
						if(Frame.negative) {
							//��������ɹ��������ִ���������ЧҲ��������Ч�ġ�
							if(!Random.judge(newpw)) {
								//��������ɹ������벻�Ϲ�
								System.out.println("Invalid password is accepted by EN100!!!!");
								Frame.updateTextArea("Invalid password is accepted by EN100!!!!\n");	
//								t.cancel();
								if(Frame.save) {
									bw.write("Invld    "+"FAIL");
									bw.newLine();
									bw.flush();
//									bw.close(); //��t.cancel()�ĵط���Ҫclose()
//									streamClosed = true;
								}
//								if(Frame.fwpwRunning) Frame.fwpwRunning = false;
//								if(Frame.digpwRunning) Frame.digpwRunning = false;
							}else {
								//��������ɹ�,����Ϲ�
								if(Frame.save) {
									bw.newLine();
									bw.flush();
								}
							}
						}else {
							//��������ɹ������봮������Ч�ġ�
							if(Frame.save) {
								bw.newLine();
								bw.flush();
							}
						}						
					}
					numFinished++;
					if((Frame.ubound != 0)&& (numFinished == Frame.ubound)) {
						if((Frame.negative && Frame.checkUbound())	//������ԣ���checkUbound()��־��Ϊtrue
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