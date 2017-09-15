package security;

import java.io.BufferedOutputStream;
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
	private static BufferedReader in = null;
	public static int succ = 0;
	private static int attempt;
	private static int timeout;
	private static String curpw;
	private static String newpw;
	private static String pwNotExist = "Confirm password:";//ֻ������û�裬��ҳ����д��ַ���
	private static String pwExistAlready = "Confirm new password:"; //��̬��ѯ�Ƿ�������룬ֻ��һ�Ρ���̬���������Ƿ���ɹ��� pwSet
	private static String pwSet = "The password has been set or changed";
	private static String boundary = "----thisisfromEn100securityteam-sunxinfeng";
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

//	private static PrintWriter out = null;
	private static BufferedOutputStream out = null;
	private static boolean setPwSucc; //����������ɹ�
	private static boolean setPwSucc_LastTime; //�ϴ�������ɹ��������жϷ񶨲���ʱ������Ҫ��Ҫȡ�ϴε�������Ϊ��ǰ���롣����ϴ�����ʧ�ܣ���ȡ����ǰ���뱣�����ϴεġ�
	public static boolean pwExist;		//����������
	private static boolean pwInitInternal;	//�����Ƿ��ɱ������ʼ��
	private static boolean AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram;
	public static Timer t = null;//Make the timer be public so that the pw setting process can be terminated by 'Reset' in Frame.java by t.cancel()
	public static boolean t_running;
	public static boolean self = true; //Ϊ��ʱ�����Լ���Ӧ�����루��������DigPW���͸�digsi ����)��Ϊ��ʱ������һ������(�����DigPW����fw ����)��
			//Ϊ��ʱ����Ҫ�������븳����ǰ���룬Ȼ���ٻ��һ�������롣Ϊ��ʱ���ò���ĵ�ǰ�����������������ַ�µ����롣��һ�����������Ρ�
//	public static boolean lock;//���������ַ�ʱ��ȷ����ǰ�����������һ�ࡣ

//	public static void main(String[] s) {
	public static void set() {
		numFinished = 0;
		pwInitInternal = false; // Ĭ�ϼ������벻���ɱ������ʼ����.->�����ж��ڸ�����ʱ,���������Դ.
								// �����if-else-���,else����Ҫ�ν�һ������if���ı��� newpw
//		pwExist = false; //ʹ��attackʱ����prepare��������ΪpwExistΪtrue,�����������ֱ����ˣ��߼����ԡ�������Ƶ�reset()�
		attempt = 0;	//�������Դ�����
		AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram = false; //���������Ƿ���һ̨��������ֳɵ�װ��(��û��initialize��������)��		
		if(FrameSecurity.save) {
			streamClosed = false;
			try {
				bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
		}
		timeout = FrameSecurity.period*100;
		t = new Timer();
		SetPasswordCycically setPasswordCycically = new SetPasswordCycically();
		t.schedule(setPasswordCycically, 0, timeout);
		
	}

	/**
	 * ����EN100��HTTP������,������ɹ��������ٴ�����setpassword,EN100������ȷ�������������õ�״̬.
	 */
	static class SetPasswordCycically extends TimerTask {
		
		String str = null;
//		String result = "";

		public void run() {
			t_running = true;
			end = false;
			if (!FrameSecurity.stop) {
				try {
					if(self)
						url = new URL(FrameSecurity.ip);
					else
						url = new URL(FrameSecurity.ip_another);
					setPwSucc = false;
//					pwExist = true; 

					if (!pwExist) {
						// conn����������Ƿ��Ѿ����á�
						if (FrameSecurity.tls) {
							conn = setHttpsConnect((HttpsURLConnection) url.openConnection());
							sc = SSLContext.getInstance("TLS");
							sc.init(null, new TrustManager[] { new MyTrust() }, new java.security.SecureRandom());
							((HttpsURLConnection) conn).setSSLSocketFactory(sc.getSocketFactory());
						} else {
							conn = setHttpConnect((HttpURLConnection) url.openConnection());
						}
//						boundary = "----thisisfromEn100securityteam-sunxinfeng";

						in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
						while ((str = in.readLine()) != null) {
							if (str.indexOf(pwExistAlready) > -1) { // һ��⵽����ַ���,����Ϊ�����Ѿ�����.
								pwExist = true;
								break;
							}
						}
						if (FrameSecurity.tls) {
							((HttpsURLConnection) conn).disconnect(); // HttpURLConnectionֻ����д���,�ҶϿ����ܸ���.
																		// �˴�ȡ����־λ,�Ͽ�conn, ��������һ��connection.
						} else {
							((HttpURLConnection) conn).disconnect();
						}
					}
					//connection �����������롣
					if(FrameSecurity.tls) {
						connection = setHttpsConnect((HttpsURLConnection) url.openConnection());
						sc = SSLContext.getInstance("TLS");
						sc.init(null, new TrustManager[] {new MyTrust()}, new java.security.SecureRandom());
						((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
					}else {
						connection = setHttpConnect((HttpURLConnection) url.openConnection());
					}
					
					connection.setDoInput(true);
					connection.setDoOutput(true);
					if (!pwExist) {
							StringBuffer set = new StringBuffer();
							newpw = FrameSecurity.commonpw; // ��һ�������룬���������ġ�
							set.append("--" + boundary + "\r\n")
									.append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n")
									.append(newpw).append("\r\n--" + boundary + "\r\n")
									.append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n")
									.append(newpw).append("\r\n--" + boundary + "--\r\n");
							// out = new PrintWriter(connection.getOutputStream());
							out = new BufferedOutputStream(connection.getOutputStream());
							out.write(set.toString().getBytes("UTF-8"));
							out.flush();

							in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
							while ((str = in.readLine()) != null) {
								if (str.indexOf(pwSet) != -1) {
									succ += 1;
									setPwSucc = true;
									setPwSucc_LastTime = true;
									pwInitInternal = true;
									pwExist = true;
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
							if (setPwSucc_LastTime) { // �ϴμ���ʼ���ǴΣ���Ȼ�ǳɹ��ġ��ж���������Ҳ�С�
								if (self) {
									curpw = newpw;
									setPwSucc_LastTime = false;
								}
							}
							pwInitInternal = false; // pwInitInternalֻ����һ�Σ�����һ�κ��Ҫ���false 8/25
						} else {
							if (setPwSucc_LastTime) {
								if (self) {
									curpw = newpw; // �Ѿ��ɱ�����Ĺ�һ�����룬���Բ����ⲿȡ��ǰ����,�������ϴ��޸ĳɹ���ǰ����ȡ�ϴε����롣
									setPwSucc_LastTime = false;
								}
							} else {
								if (!AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram) {
									curpw = FrameSecurity.commonpw;
									if (FrameSecurity.attack) {//9.4.2017 ��attack�ӽ���ʱ���¼ӵ��߼�����ʹ�����ж�������newpw���ﱻ��ֵ����if(self)����ĳ�����Ҫ��ֵ��
										newpw = Random.getValidRandomString();
									}
								} else { // 9.4.2017 ��attack�ӽ���ʱ���¼ӵ��߼���
									if (FrameSecurity.attack) {
										curpw = newpw;
										newpw = Random.getValidRandomString();
									}
								}
							}
						}
						StringBuffer change = new StringBuffer();
						if (self) {
							if (!FrameSecurity.attack) {// 9.4.2017 ����attackʱ���¼ӵ��߼���
								if (FrameSecurity.negative) {
									newpw = Random.getRandomString();
								} else {
									if (!FrameSecurity.traverse) {
										// �����б�������������case
										newpw = Random.getValidRandomString();
									} else {
										// lock = FrameSecurity.prepare_traverse();
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
						change.append("--" + boundary + "\r\n")
								.append("Content-Disposition: form-data; name=\"curr_password\"\r\n\r\n").append(curpw)
								.append("\r\n--" + boundary + "\r\n")
								.append("Content-Disposition: form-data; name=\"init_password\"\r\n\r\n").append(newpw)
								.append("\r\n--" + boundary + "\r\n")
								.append("Content-Disposition: form-data; name=\"con_password\"\r\n\r\n").append(newpw)
								.append("\r\n--" + boundary + "--\r\n");

						// out = new PrintWriter(connection.getOutputStream());
						out = new BufferedOutputStream(connection.getOutputStream());
						out.write(change.toString().getBytes("UTF-8"));
						out.flush();

						AttemptToCHANGE_NotInitializePwAtLeastOnceByThisProgram = true;

						in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
						while ((str = in.readLine()) != null) {
							// result += (str + "\n"); //�������лᵼ��'OutOfMemoryError: Java heap space',
							// ��Ϊ'result'û����Ϊ ""��ÿ��ѭ�������ۼӡ�
							if (str.indexOf(pwSet) != -1) {
								// System.out.println(str);
								succ += 1;
								setPwSucc = true;
								setPwSucc_LastTime = true;
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
					//e.g.: abc123!@	Invalid		fail
					if(FrameSecurity.save) {
//						bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File("logs.txt"))));
						fmt = new Formatter();
						fmt.format("%-32s", newpw);
						bw.write(fmt.toString()); //�ֶ�ֹͣʱ������Reset����������رգ�Ȼ���Ѿ��ɶ�ʱ���𵽵ĵ�ǰ��һ�β����������һ�Σ���Ҫ�õ�����������
								//�ʿ��ܻ����NPE�� 
					}

					if (!setPwSucc) {
						if(!FrameSecurity.attack) {
						if(!FrameSecurity.negative) {
							//�������ʧ�ܣ������붼�ǺϹ�ġ�
							System.out.println("Set password failed. Process terminated. Is the current pw correct?");
							FrameSecurity.updateTextArea("Set password failed. Process terminated.\nIs the current pw correct?\n");						
							t.cancel();
							if(FrameSecurity.save) {
								bw.write("Valid    "+"FAIL");
								bw.newLine();
								bw.flush();
								bw.close(); //��t.cancel()�ĵط���Ҫclose()
								streamClosed = true;
							}
							if(FrameSecurity.fwpwRunning) FrameSecurity.fwpwRunning = false;
							if(FrameSecurity.digpwRunning) FrameSecurity.digpwRunning = false;
						}else {
						    //�������ʧ�ܣ���ʱ�������ַ���δ���ǺϹ�ģ�Ҫ���жϡ�
							if(Random.judge(newpw)) {
								System.out.println("Set password failed. Is the current pw correct?");
								FrameSecurity.updateTextArea("Set password failed. \nIs the current pw correct?\n");	
								t.cancel(); //���������������Чȴ�޸�ʧ��ʱͣloop��
								if(FrameSecurity.save) {
									bw.write("Valid    "+"FAIL");
									bw.newLine();
									bw.flush();
									bw.close(); //��t.cancel()�ĵط���Ҫclose()
									streamClosed = true;
								}
//								if(Frame.fwpwRunning) Frame.fwpwRunning = false;
//								if(Frame.digpwRunning) Frame.digpwRunning = false;
							}else {
								System.out.println("Invalid password is rejected by EN100.");
								FrameSecurity.updateTextArea("Invalid password is rejected by EN100.\n");
								if(FrameSecurity.save) {
									bw.write("Invld    "/*+"PASS"*/);
									bw.newLine();
									bw.flush();
								}
							}}
						}
												
					}else {//��������ɹ�						
						if(FrameSecurity.negative) {
							//��������ɹ��������ִ���������ЧҲ��������Ч�ġ�
							if(!Random.judge(newpw)) {
								//��������ɹ������벻�Ϲ�
								System.out.println("Invalid password is accepted by EN100!!!!");
								FrameSecurity.updateTextArea("Invalid password is accepted by EN100!!!!\n");	
//								t.cancel();
								if(FrameSecurity.save) {
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
								if(FrameSecurity.save) {
									bw.newLine();
									bw.flush();
								}
							}
						}else {
							//��������ɹ������봮������Ч�ġ�
							if(FrameSecurity.save) {
								bw.newLine();
								bw.flush();
							}
						}						
					}
					if (FrameSecurity.traverse) {
						if (!pwInitInternal)
							numFinished++; // ����ʱ��ʼ����β��㡣����ʼ��Ҳ���ȥ����ʹindex��1�����ַ�������ÿ���ַ�����һ���ַ�(�ո�/A/a/0)ȡ�����ˡ�
					} else
						numFinished++;
					if (!FrameSecurity.traverse) {
						if ((FrameSecurity.ubound != 0) && (numFinished == FrameSecurity.ubound)) {
							if ((FrameSecurity.negative && FrameSecurity.checkUbound()) // ������ԣ���checkUbound()��־��Ϊtrue
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
								//ÿ������һ���ַ����Ѹ���traverse��ѡ��Ĺ�ȥ����Ȼ�����ǲ��ǻ�������Ҫ�������ࡣ����У���
								//����numFinished����Ȼ������һ���ַ���ʱ���Ǵ�ͷ��ʼ�������ǽ�����һ���ַ������һ������š�
								numFinished = 0; 
							}
							if ((t != null) && (!FrameSecurity.traverse))
								t.cancel();
						}
					}
					in.close();
					out.close();

					if(FrameSecurity.tls) { //9.2.2017
						((HttpsURLConnection) connection).disconnect(); 				
					}else {
						((HttpURLConnection) connection).disconnect();
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
			c.setRequestProperty("User-Agent", "sunxinfeng");
			c.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
			c.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
			c.setRequestProperty("Accept-Encoding", "gzip, deflate");
			c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
			c.setConnectTimeout(2000); // timeout
			c.setReadTimeout(2000);
			return c;
		}
		private HttpURLConnection setHttpConnect(HttpURLConnection c) {
			c.setRequestProperty("User-Agent", "sunxinfeng");
			c.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
			c.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
			c.setRequestProperty("Accept-Encoding", "gzip, deflate");
			c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
			c.setConnectTimeout(2000); // timeout
			c.setReadTimeout(2000);
			return c;
		}		
	}
}