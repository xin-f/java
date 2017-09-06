package security;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.text.DefaultCaret;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Timer;
import java.util.TimerTask;
import java.awt.event.ActionEvent;
import javax.swing.JRadioButton;
import javax.swing.JComboBox;
import javax.swing.JToggleButton;
import javax.swing.JCheckBox;

public class FrameSecurity {

	private static JFrame SecurityTest;
	private static JTextArea textArea;
	private static JTextArea textArea_cnt;
	public static JTextField textField_ip;
	private static JLabel PERIOD;
	private static JTextField textField_period;
	private static JTextField textField_FwPw;
	private static JTextField textField_fw;
	private static JCheckBox chkbxsave;	
	private static JCheckBox chkbxTls;
	private static JCheckBox chkbxAlt;
	
	public static String ip;
	public static String ip_another;
	public static int period;
	public static String fwpw;
	public static String digpw;
	public static String commonpw;//fwpw 和digpw 由同一个函数管理，这个公共密码用来在fwpw和digpw都没设时，点不同按钮，能把界面上相应两个字符串送到不同密码。用在SetPassword里
	public static String fw;
	public static boolean fwpwRunning; //password is being set. 用于点Reset后停止改密码的loop, 以及与其它操作的互斥。 
	public static boolean digpwRunning; //password is being set. 用于点Reset后停止改密码的loop, 以及与其它操作的互斥。
	public static boolean fwRunning; //fw is being uploaded. 用于点Reset后停止改密码的loop, 以及与其它操作的互斥。
	public static boolean chkRunning; //检查证书. 用于与其它操作的互斥。
	public static boolean negRunning; //反向测试运行中，即1-24位随机字符串设密码。也不一定都是反向测试，存在字符串满足密码条件的情况。
	public static boolean debug;
	public static boolean ForFun;	//get the certificate such as baidu.com
	public static boolean negative;
	public static int ubound; //循环次数达到此值即停。
	private static File file = null;
	private static PrintStream logStream = null;
	private static JTextField textField_DigPw;
	private static JRadioButton rdbtnD;
	private static JRadioButton rdbtnF;
	private static JTextArea textArea_ubound;
	public static JCheckBox chkbxA;
	public static JCheckBox chkbxa;
	public static JCheckBox chkbx0;
	public static JCheckBox chkbx_;
	
	private static Timer t_ping = null; //新建一线程检查server是否在线。默认启动，Reset复归，每个操作都会再启动。
	private static boolean t_ping_running = false;
	public static boolean serverLost = false;
	
	private static Thread thread_neg = null;
	public static boolean stop;
	public static boolean save;
	public static boolean tls;
	public static FrameSecurity window;
	public static boolean alter;
	public static boolean traverse;
	public static boolean traverseA;
	public static boolean traversea;
	public static boolean traverse0;
	public static boolean traverse_;
	public static boolean turn;
	
	public static boolean attack;
	
	public enum Optype{digsi,fw}
	public enum Charset{upp,low,dig,cha}
	public static Charset charset;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					window = new FrameSecurity();					
					buildTextArea();
					SecurityTest.setVisible(true);

//					t_ping = new Timer(); 
//					t_ping.schedule(window.new Ping(), 0, 10000);
//					t_ping_running = true;
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public FrameSecurity() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		SecurityTest = new JFrame();
		SecurityTest.setTitle("Security Test");
		SecurityTest.setBounds(100, 100, 399, 360);
		SecurityTest.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		SecurityTest.getContentPane().setLayout(null);
		
		JLabel IPADDR = new JLabel("IP");
		IPADDR.setBounds(10, 11, 17, 22);
		SecurityTest.getContentPane().add(IPADDR);
		
		textField_ip = new JTextField();
		textField_ip.setBounds(26, 12, 86, 20);
		textField_ip.setText("172.20.1.25");
		SecurityTest.getContentPane().add(textField_ip);
		textField_ip.setColumns(10);
		
		PERIOD = new JLabel("Prid(0.1s)");
		PERIOD.setBounds(122, 15, 55, 14);
		SecurityTest.getContentPane().add(PERIOD);
		
		textField_period = new JTextField();
		textField_period.setToolTipText("Ends with \".\" will enable password attack, e.g., \"10.\" means making an attempt every 1 sec");
		textField_period.setBounds(179, 12, 30, 20);
		textField_period.setText("100");
		SecurityTest.getContentPane().add(textField_period);
		textField_period.setColumns(10);
		
		JButton btnFwPW = new JButton("FwPW"); //Set Firmware upload password
		btnFwPW.setToolTipText("Set FW upload password cyclically with specified PERIOD.");
		btnFwPW.setBounds(210, 61, 86, 23);
		btnFwPW.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				/*if(!t_ping_running) {
					t_ping = new Timer();
					t_ping.schedule(new Ping(), 0, 5000);
					t_ping_running = true;
				}*/
				enablePing();
				alter = chkbxAlt.isSelected();
				alter = chkbxAlt.isSelected();
				if(alter) {
					ip_another = getIP(textField_ip.getText(),Optype.digsi);
				}
				stop = false;
				attack = false;
				ubound = 0;
				if((!fwRunning) && (!digpwRunning) && (!fwpwRunning)){
					debug = false;
					fwpwRunning = true;
					ubound = 0;
					prepare_setFwPW();
					checkUbound();
					prepare_traverse();
					if(debug){
						file = new File("log.txt");
						try {
							logStream = new PrintStream(new FileOutputStream(file));
						} catch (FileNotFoundException e1) {
							e1.printStackTrace();
						}
						System.setOut(logStream);
						System.setErr(logStream);
					}
					if (attack) {
						SetPassword.set();
					} else {
						if (period < 50) {
							updateTextArea("To avoid timeout, set the period no less than 5s.\n");
						}else
							SetPassword.set();
					}
				}else if(fwRunning){
					updateTextArea("FW uploading is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(digpwRunning){
					updateTextArea("Digsi connection pw Setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(fwpwRunning){
					updateTextArea("The operation is already in progress!! \n");
				}				
			}
		});
		SecurityTest.getContentPane().add(btnFwPW);
		
		JLabel lblDigpw = new JLabel("DigPW");
		lblDigpw.setBounds(10, 34, 40, 22);
		SecurityTest.getContentPane().add(lblDigpw);
		
		textField_DigPw = new JTextField();
//		textField_DigPw.setText("21!qQ/nm`hMi),52(x@= /nm`hMi),52(x@= /nm`hMi),52(x@= /nm`hMi),52(x@=");
		textField_DigPw.setText("1!qQ1234");
		textField_DigPw.setColumns(10);
		textField_DigPw.setBounds(54, 35, 155, 20);
		SecurityTest.getContentPane().add(textField_DigPw);
		
		JButton btnDigPW = new JButton("DigPW");
		btnDigPW.setToolTipText("Set Digsi connection password cyclically with specified PERIOD.");
		btnDigPW.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				/*if(!t_ping_running) {
					t_ping = new Timer();
					t_ping.schedule(new Ping(), 0, 5000);
					t_ping_running = true;
				}*/
				enablePing();
				alter = chkbxAlt.isSelected();
				if(alter) {
					ip_another = getIP(textField_ip.getText(),Optype.fw);
				}
				stop = false;
				attack = false;
				ubound = 0;
				if((!fwRunning) && (!fwpwRunning) && (!digpwRunning)){
					debug = false;
					digpwRunning = true;
					ubound = 0;
					prepare_setDigPW();
					checkUbound();
//					if(prepare_traverse()>1) {
//						return; //遍历的字符类型大于一个，退出当前方法，重新选。
//					}
					prepare_traverse();
					if(debug){
						file = new File("log.txt");
						try {
							logStream = new PrintStream(new FileOutputStream(file));
						} catch (FileNotFoundException e1) {
							e1.printStackTrace();
						}
						System.setOut(logStream);
						System.setErr(logStream);
					}
					if (attack) {
						SetPassword.set();
					} else {
						if (period < 50) {
							updateTextArea("To avoid timeout, set the period no less than 5s.\n");
						}else
							SetPassword.set();
					}
				}else if(fwRunning){
					updateTextArea("FW uploading is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(fwpwRunning){
					updateTextArea("FW upload pw Setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(digpwRunning){
					updateTextArea("The operation is already in progress!! \n");
				}
			}
		});
		btnDigPW.setBounds(210, 35, 86, 23);
		SecurityTest.getContentPane().add(btnDigPW);
		
		JButton btnReset = new JButton("R");
		btnReset.setToolTipText("Reset");
		btnReset.setBounds(210, 115, 42, 23);
		btnReset.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				reset();
			}
		});
		SecurityTest.getContentPane().add(btnReset);
		
		JButton btnClear = new JButton("C");
		btnClear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				textArea.setText("");
				updateTextAreacnt(0);
			}
		});
		btnClear.setToolTipText("Clear");
		btnClear.setBounds(254, 115, 42, 23);
		SecurityTest.getContentPane().add(btnClear);
		
		
		
		JLabel lblNumberOfTimes = new JLabel("Cnt of succ oper:");
		lblNumberOfTimes.setBounds(10, 117, 100, 22);
		SecurityTest.getContentPane().add(lblNumberOfTimes);
		
		JLabel lblFwPw = new JLabel("FwPW");
		lblFwPw.setBounds(10, 61, 40, 22);
		SecurityTest.getContentPane().add(lblFwPw);
		
		textField_FwPw = new JTextField();
		textField_FwPw.setBounds(54, 62, 155, 20);
//		textField_FwPw.setText("ddfasdfsASDDFSDf4654+65.;''.ddfasdfsASDDFSDf4654+65.;''.'';,!*(#^#^#, ");
		textField_FwPw.setText("12341!qQ");
		textField_FwPw.setColumns(10);
		SecurityTest.getContentPane().add(textField_FwPw);

		JLabel lblFw = new JLabel("FW");
		lblFw.setBounds(10, 89, 40, 22);
		SecurityTest.getContentPane().add(lblFw);
		
		textField_fw = new JTextField();
		textField_fw.setBounds(54, 90, 155, 20);
		textField_fw.setText("D:\\IEC61850_81.pck");
		textField_fw.setColumns(10);
		SecurityTest.getContentPane().add(textField_fw);
		
		JButton btnUpldfw = new JButton("UpldFW");
		btnUpldfw.setToolTipText("Upload FW cyclically with specified PERIOD.");
		btnUpldfw.setBounds(210, 87, 86, 23);
		btnUpldfw.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				/*if(!t_ping_running) {
					t_ping = new Timer();
					t_ping.schedule(new Ping(), 0, 5000);
					t_ping_running = true;
				}*/
				enablePing();
				if((!fwpwRunning)&&(!digpwRunning)&&(!fwRunning)){
					debug = false;
					fwRunning = true;
					ubound = 0;
					prepare_upldFW();
					checkUbound();
					if(debug){
						file = new File("log.txt");
						try {
							logStream = new PrintStream(new FileOutputStream(file));
						} catch (FileNotFoundException e1) {
							e1.printStackTrace();
						}
						System.setOut(logStream);
						System.setErr(logStream);
					}
					if(period < 600){
						updateTextArea("To avoid timeout, set the period no less than 60s.\n");
					}else{
						updateTextArea("\"Update in progress\" being detected is \\\nregarded as updating successfully.\n");
						HttpPost.upldFW();
					}
				}
				else  if(fwpwRunning){
					updateTextArea("FW upload pw setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else  if(digpwRunning){
					updateTextArea("Digsi connection pw setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(fwRunning){
					updateTextArea("FW uploading is already in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}
			}
		});
		SecurityTest.getContentPane().add(btnUpldfw);
		
		JButton btnCert = new JButton("ChkCert");
		btnCert.setToolTipText("Check server certificate.");
		btnCert.setBounds(210, 11, 86, 23);
		btnCert.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				/*if(!t_ping_running) {
					t_ping = new Timer();
					t_ping.schedule(new Ping(), 0, 5000);
					t_ping_running = true;
				}*/
				enablePing();
				if((!fwpwRunning)&&(!digpwRunning)&&(!fwRunning)){
					chkRunning = true;
					updateTextArea("Checking certificate:\n");				
					debug = false;
					prepare_ChkCert();
					if(debug){
						file = new File("log.txt");
						try {
							logStream = new PrintStream(new FileOutputStream(file));
						} catch (FileNotFoundException e1) {
							e1.printStackTrace();
						}
						System.setOut(logStream);
						System.setErr(logStream);
					}
					if(tls)
						GetCertificate.checkCert();						
				}else  if(fwpwRunning){
					updateTextArea("FW upload pw setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else  if(digpwRunning){
					updateTextArea("Digsi connection pw setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(fwRunning){
					updateTextArea("FW uploading is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}			
			}
		});
		SecurityTest.getContentPane().add(btnCert);
		
		JButton btnNegPw = new JButton("NegPw");
		btnNegPw.setToolTipText("Negative test.");
		btnNegPw.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				enablePing();
				stop = false;
				negative = true;
				negRunning = true;	
				ubound = 0;
				prepare_setNegPW();	
//				prepare_traverse();
				checkUbound();
				Thread_neg a = new Thread_neg();
				thread_neg = new Thread(a);
				thread_neg.start();
				
			}
		});
		btnNegPw.setBounds(300, 34, 75, 23);
		SecurityTest.getContentPane().add(btnNegPw);
		

		rdbtnD = new JRadioButton("D");
		rdbtnD.setToolTipText("set digsi connection pw");
		rdbtnD.setBounds(302, 61, 33, 23);
		SecurityTest.getContentPane().add(rdbtnD);
		
		rdbtnF = new JRadioButton("F");
		rdbtnF.setToolTipText("set fw upload pw");
		rdbtnF.setSelected(true);
		rdbtnF.setBounds(337, 61, 32, 23);
		SecurityTest.getContentPane().add(rdbtnF);
		
		ButtonGroup bg = new ButtonGroup();
		bg.add(rdbtnD);
		bg.add(rdbtnF);
		
		JButton btnExit = new JButton("Exit");
		btnExit.setBounds(300, 11, 75, 23);
		btnExit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(save && (SetPassword.bw != null)) {
					try {
						SetPassword.bw.flush();
						SetPassword.bw.close();
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				}
				System.exit(0);
			}
		});
		SecurityTest.getContentPane().add(btnExit);	

		/*JButton btnMemo = new JButton("Memo");
		btnMemo.setToolTipText("Short description.");
		btnMemo.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				updateTextArea("ChkCert: Read the certificate from server. Only IP part of the certificate will be checked.\n" + 
						"DigPW: Initialize or change digsi conneciton password. If there's no password existing, initialize one "
						+ "with string in the left box;If there's already password existing, input the current password to the "
						+ "left box and this applet will change the password with randomly generated password which conforms the "
						+ "rules cyclically with specified PERIOD.  The loop will stop if set password fails.\n" + 
						"FwPW: Same as DigPW but for firmware upload password.\n" + 
						"NegPW: together with D(digsi connection) or F(firmware upload), to test 1~24 length random string, maybe "
						+ "Valid, probably Invalid password. Just like  'DigPW' or 'FwPW' but loop will not stop automatically.\n" + 
						"save: Enable saving. If selected, 'ChkCert' will save certificate; 'DigPW', 'NegPW' and 'FwPW' "
						+ "will save all the passwords which are set successfully.\n");
				
			}
		});
		btnMemo.setBounds(300, 87, 75, 23);
		SecurityTest.getContentPane().add(btnMemo);*/
		

		chkbxsave = new JCheckBox("save");
		chkbxsave.setSelected(true);
		chkbxsave.setToolTipText("Save the log");
		chkbxsave.setBounds(315, 135, 60, 23);
		SecurityTest.getContentPane().add(chkbxsave);		

		chkbxTls = new JCheckBox("tls");
//		chkbxTls.setSelected(true);
		chkbxTls.setToolTipText("Enable https function");
		chkbxTls.setBounds(315, 161, 50, 23);
		SecurityTest.getContentPane().add(chkbxTls);
		
		chkbxAlt = new JCheckBox("alter");
		chkbxAlt.setToolTipText("Set password alternately");
		chkbxAlt.setBounds(315, 187, 60, 23);
		SecurityTest.getContentPane().add(chkbxAlt);
		
//		JTextArea
		textArea_cnt = new JTextArea();
		textArea_cnt.setBounds(115, 119, 30, 18);
		textArea_cnt.setText("0");
		SecurityTest.getContentPane().add(textArea_cnt);

		textArea_ubound = new JTextArea();
		textArea_ubound.setToolTipText("Number of times the loop will run.");
		textArea_ubound.setText("0");
		textArea_ubound.setBounds(167, 119, 30, 18);
		SecurityTest.getContentPane().add(textArea_ubound);
		

		chkbxA = new JCheckBox("A");
		chkbxA.setToolTipText("");
		chkbxA.setBounds(302, 89, 35, 23);
		SecurityTest.getContentPane().add(chkbxA);
		
		chkbxa = new JCheckBox("a");
		chkbxa.setToolTipText("");
		chkbxa.setBounds(340, 89, 35, 23);
		SecurityTest.getContentPane().add(chkbxa);
		
		chkbx0 = new JCheckBox("0");
		chkbx0.setToolTipText("");
		chkbx0.setBounds(302, 115, 35, 23);
		SecurityTest.getContentPane().add(chkbx0);
		
		chkbx_ = new JCheckBox("!");
		chkbx_.setToolTipText("");
		chkbx_.setBounds(340, 115, 35, 23);
		SecurityTest.getContentPane().add(chkbx_);
		
	}
	
	private static void buildTextArea(){
		textArea = new JTextArea();
//		textArea.setBounds(10, 90, 275, 161);
//		frame.getContentPane().add(textArea);
		JScrollPane js=new JScrollPane(textArea);
		js.setBounds(10, 140, 300, 170);
		SecurityTest.getContentPane().add(js);	
				
		DefaultCaret caret = (DefaultCaret) textArea.getCaret(); // 这两行让文本框的滚动条自动在最下面.
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		textArea.setLineWrap(true); 			//自动换行
		textArea.setWrapStyleWord(true);		//自动换行不断字
		
		
		js.setVisible(true);
	}
	public static void updateTextArea(String str) { 
		textArea.append(str);
    } 
	public static void updateTextAreacnt(int i) {
		textArea_cnt.setText(Integer.toString(i));
    } 
	
	public static boolean prepare_traverse(/*Charset cs*/) {
		int i = 0;
		traverse = false;
		turn = false;
		traverseA = chkbxA.isSelected();
		traversea = chkbxa.isSelected();
		traverse0 = chkbx0.isSelected();
		traverse_ = chkbx_.isSelected();
		if(traversea) {
			ubound = 26;
			charset = Charset.low;
			i++;
			traverse = true;
		}
		if(traverseA ) {
			ubound = 26;
			charset = Charset.upp;
			i++;
			traverse = true;
		}
		if(traverse0) {
			ubound = 10;
			charset = Charset.dig;
			i++;
			traverse = true;
		}			
		if(traverse_) {
			ubound = 33;
			charset = Charset.cha;
			i++;
			traverse = true;
		}
		if(i > 1) {
//			updateTextArea("Select at most 1 type.\n");
			//如果想在这里调用reset()退出，没用。reset()执行完后会继续执行写密码的方法后面的部分。
			turn = true;
		}
		return turn;
	}
	
	/**
	 * 识别输入的IP, PERIOD, 老密码.
	 * 密码后加五个星(*****)输出Log.
	 */
	public static void prepare_setFwPW(){
		String str;
		String tmp;
		int len;
		save = chkbxsave.isSelected();
		tls = chkbxTls.isSelected();
		if(save)
			SetPassword.file = new File("Log_fwPw.txt");
		if(tls)
			ip = "https://"+textField_ip.getText()+"/setfwuploadpassword";
		else
			ip = "http://"+textField_ip.getText()+"/setfwuploadpassword";
		tmp = textField_period.getText();
		if(tmp.endsWith(".")) {
			tmp = tmp.substring(0, tmp.length()-1);
			attack = true;
			updateTextArea("Password attempting:\n");
			SetPassword.pwExist = true; //既然要攻击，就认为密码存在。
		}
		period = Integer.parseInt(tmp);
		str = textField_FwPw.getText();
		commonpw = str;
		len = str.length();
		if(str.endsWith("*****")){
			debug = true;
			fwpw = str.substring(0, len - 5);
		}
		else fwpw = str;
	}
	
	/**
	 * 识别输入的IP, PERIOD, 老密码.
	 * 密码后加五个星(*****)输出Log.
	 */
	public static void prepare_setDigPW(){
		String str;
		String tmp;
		save = chkbxsave.isSelected();
		tls = chkbxTls.isSelected();
		if(save)
			SetPassword.file = new File("Log_digsiPw.txt");
		int len;
		if(tls)
			ip = "https://"+textField_ip.getText()+"/setconnectionpassword";
		else
			ip = "http://"+textField_ip.getText()+"/setconnectionpassword";
		tmp = textField_period.getText();
		if(tmp.endsWith(".")) {
			tmp = tmp.substring(0, tmp.length()-1);
			attack = true;
			updateTextArea("Password attempting:\n");
			SetPassword.pwExist = true; //既然要攻击，就认为密码存在。
		}
		period = Integer.parseInt(tmp);
		str = textField_DigPw.getText();
		commonpw = str;
		len = str.length();
		if(str.endsWith("*****")){
			debug = true;
			digpw = str.substring(0, len - 5);
		}
		else digpw = str;
	}	

	/**
	 * 识别输入的IP, PERIOD, 老密码.
	 * 密码后加五个星(*****)输出Log.
	 */
	public static void prepare_setNegPW(){
		String str;
		int len;
		save = chkbxsave.isSelected();
		tls = chkbxTls.isSelected();
		if(rdbtnD.isSelected()) {
			if(save)
				SetPassword.file = new File("Log_negdigsiPw.txt");
			if(tls)
				ip = "https://"+textField_ip.getText()+"/setconnectionpassword";
			else
				ip = "http://"+textField_ip.getText()+"/setconnectionpassword";
			period = Integer.parseInt(textField_period.getText());
			str = textField_DigPw.getText();
			commonpw = str;
			len = str.length();
			if(str.endsWith("*****")){
				debug = true;
				digpw = str.substring(0, len - 5);
			}
			else digpw = str;
		}
		if(rdbtnF.isSelected()) {
			if(save)
				SetPassword.file = new File("Log_negfwPw.txt");
			if(tls)
				ip = "https://"+textField_ip.getText()+"/setfwuploadpassword";
			else
				ip = "http://"+textField_ip.getText()+"/setfwuploadpassword";
			period = Integer.parseInt(textField_period.getText());
			str = textField_FwPw.getText();
			commonpw = str;
			len = str.length();
			if(str.endsWith("*****")){
				debug = true;
				fwpw = str.substring(0, len - 5);
			}
			else fwpw = str;
		}
	}
	
	/**
	 * 识别输入的IP, PERIOD, FW 路径.
	 * 路径后加一个星(*),输出Log.
	 */
	public static void prepare_upldFW(){
		String str;		
		int len;
		tls = chkbxTls.isSelected();
		if(tls)
			ip = "https://"+textField_ip.getText()+"/upload";
		else
			ip = "http://"+textField_ip.getText()+"/upload";
		period = Integer.parseInt(textField_period.getText());
		str = textField_fw.getText();
		len = str.length();
		if (str.endsWith("*")){
			fw = str.substring(0, len - 1);
			debug = true;
		}else
			fw =str;
		fwpw = textField_FwPw.getText();		
	}
	/**
	 * 识别输入的IP.
	 * period为99时,输出Log.
	 */
	public static void prepare_ChkCert(){
		String str = textField_ip.getText();
		save = chkbxsave.isSelected();
		tls = chkbxTls.isSelected();
		if(save)
			GetCertificate.file = new File("cert.txt");
		if(str.indexOf("https") == -1) {
			if(str.matches("[a-zA-Z]+")) { //不玩了，GetCertificate.java里已去掉相关代码。
				ForFun = true;
				ip = "https://www."+str+".com";
			}else{
				if(!tls) {
					updateTextArea("Enable tls first.\n");					
				}else {
					ForFun = false;
					ip = "https://"+str+"/home";
					period = Integer.parseInt(textField_period.getText());
					if (period == 99)
						debug = true;
				}							
			}
		}		
//		if(str.indexOf("https") > -1) {
		else {			
			ForFun = true;
			ip = str;
		}
	}
	
	/**
	 * 检查循环次数上限，读一个值，设一个标志位。输入数值以加号结尾时，返回true，让反向测试也用这个次数。否则只有正向测试用这个次数。
	 * @return
	 */
	public static boolean checkUbound() {
		String str = textArea_ubound.getText();
		boolean result = false;
		if(str.endsWith("+")) {
			result = true;
			str = str.substring(0, str.length()-1);
		}
		ubound = Integer.parseInt(str);
		return result;
	}
	
	/**
	 * Encapsulate Reset to a method. Facilitate calling.
	 */
	public static void reset() {
		serverLost = false;
		traverse = false;
		SetPassword.pwExist = false;
		if(t_ping_running) {
			t_ping.cancel();
			t_ping_running = false;
		}
		if(save && (SetPassword.streamClosed == false) && (fwpwRunning || digpwRunning || negRunning)) {
			try {
				while(!SetPassword.end) {
					Thread.sleep(100);
				}
				SetPassword.bw.flush();
				SetPassword.bw.close();
				SetPassword.streamClosed = true;
				SetPassword.bw = null;
			} catch (IOException e1) {
				e1.printStackTrace();
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			} 
		}
		SetPassword.succ = 0;
		HttpPost.suc = 0;
		ubound = 0;

		if(fwRunning) {
			fwRunning = false;
			if(HttpPost.t != null) {
				HttpPost.t.cancel();
				HttpPost.t_running = false;
			}												
		}
		if(fwpwRunning || digpwRunning) {
			fwpwRunning = false;
			digpwRunning = false;
			// 如果只用t.cancel()，则计时器被取消，本次是最后一次。但本次还是会运行下去，可能会与预期不同。
			stop = true;
			if(SetPassword.t != null) {
				SetPassword.t.cancel();
				SetPassword.t_running = false;
			}						
		}
		if(thread_neg != null) {
			negRunning = false;
			negative = false;					
//			if(SetPassword.t != null)
//				SetPassword.t.cancel();
			stop = true;
		}	
	}
	
	public static String getIP(String src, Optype type) {
		String str = null;
		if (tls) {
			switch (type) {
			case digsi:
				str = "https://" + src + "/setconnectionpassword";
				break;
			case fw:
				str = "https://" + src + "/setfwuploadpassword";
				break;
			}
		} else {
			switch (type) {
			case digsi:
				str = "http://" + src + "/setconnectionpassword";
				break;
			case fw:
				str = "http://" + src + "/setfwuploadpassword";
				break;
			}
		}
		return str;
	}
	
	private static void enablePing() {
		if(!t_ping_running) {
			t_ping = new Timer();
			t_ping.schedule(window.new Ping(), 0, 10000);
			t_ping_running = true;
		}
	}
	
	
		
	 class Thread_neg extends SetPassword implements Runnable{
		@Override
		public void run() {
			if(!stop) {
				SetPassword.set();
			}						
		}					
	}
	 class Ping extends TimerTask{		 
		 public void run() {
			 try {
				InetAddress server = InetAddress.getByName(FrameSecurity.textField_ip.getText());
				if(!server.isReachable(1000)) {
					updateTextArea("Server lost!!!\n");
					t_ping.cancel();
					if(SetPassword.t_running) {
						SetPassword.t.cancel();
					} 
					if(HttpPost.t_running) {
						HttpPost.t.cancel();
					}
				}
			} catch (UnknownHostException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		 }		 
	}
}

