package security;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.text.DefaultCaret;
import javax.swing.JButton;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.awt.event.ActionEvent;

public class Frame {

	private static JFrame SecurityTest;
	private static JTextArea textArea;
	private static JTextArea textArea_cnt;
	private static JTextField textField_ip;
	private JLabel PERIOD;
	private static JTextField textField_period;
	private static JTextField textField_FwPw;
	private static JTextField textField_fw;
	
	public static String ip;
	public static int period;
	public static String fwpw;
	public static String digpw;
	public static String commonpw;//fwpw 和digpw 由同一个函数管理，这个公共密码用来在fwpw和digpw都没设时，点不同按钮，能把界面上相应两个字符串送到不同密码。用在SetPassword里
	public static String fw;
	public static boolean fwpwRunning; //password is being set. To disturb the pw setting loop when 'Reset'
	public static boolean digpwRunning; //password is being set. To disturb the pw setting loop when 'Reset'
	public static boolean fwRunning; //fw is being uploaded. To disturb the fw uploading when 'Reset'
	public static boolean debug;
	public static boolean ForFun;	//get the certificate such as baidu.com
	
	static File file = null;
	static PrintStream logStream = null;
	private static JTextField textField_DigPw;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Frame window = new Frame();					
					buildTextArea();
					SecurityTest.setVisible(true);
															
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public Frame() {
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
		textField_ip.setText("https://www.baidu.com");
		SecurityTest.getContentPane().add(textField_ip);
		textField_ip.setColumns(10);
		
		PERIOD = new JLabel("PERIOD(S)");
		PERIOD.setBounds(122, 15, 64, 14);
		SecurityTest.getContentPane().add(PERIOD);
		
		textField_period = new JTextField();
		textField_period.setBounds(183, 12, 26, 20);
		textField_period.setText("20");
		SecurityTest.getContentPane().add(textField_period);
		textField_period.setColumns(10);
		
		JButton btnFwPW = new JButton("FwPW"); //Set Firmware upload password
		btnFwPW.setBounds(219, 37, 86, 23);
		btnFwPW.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if((!fwRunning) && (!digpwRunning) && (!fwpwRunning)){
					debug = false;
					fwpwRunning = true;
					prepare_setFwPW();
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
					if(period < 5){
						updateTextArea("To avoid timeout, set the period no less than 5s.\n");
					}else{
						SetPassword.set();
					}
				}else if(fwRunning){
					updateTextArea("FW uploading is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(digpwRunning){
					updateTextArea("Digsi connection pw Setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(fwpwRunning){
					updateTextArea("Naughty guy! The operation is already in progress!! \n");
				}				
			}
		});
		SecurityTest.getContentPane().add(btnFwPW);
		
		JLabel lblDigpw = new JLabel("DigPW");
		lblDigpw.setBounds(10, 89, 40, 22);
		SecurityTest.getContentPane().add(lblDigpw);
		
		textField_DigPw = new JTextField();
		textField_DigPw.setText("0123abcd");
		textField_DigPw.setColumns(10);
		textField_DigPw.setBounds(54, 91, 155, 20);
		SecurityTest.getContentPane().add(textField_DigPw);
		
		JButton btnDigPW = new JButton("DigPW");
		btnDigPW.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if((!fwRunning) && (!fwpwRunning) && (!digpwRunning)){
					debug = false;
					digpwRunning = true;
					prepare_setDigPW();
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
					if(period < 5){
						updateTextArea("To avoid timeout, set the period no less than 5s.\n");
					}else{
						SetPassword.set();
					}
				}else if(fwRunning){
					updateTextArea("FW uploading is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(fwpwRunning){
					updateTextArea("FW upload pw Setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}else if(digpwRunning){
					updateTextArea("Naughty guy! The operation is already in progress!! \n");
				}
			}
		});
		btnDigPW.setBounds(219, 88, 86, 23);
		SecurityTest.getContentPane().add(btnDigPW);
		
		JButton btnReset = new JButton("Reset");
		btnReset.setBounds(219, 115, 86, 23);
		btnReset.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				SetPassword.succ = 0;
				HttpPost.suc = 0;
				textArea.setText("");
				updateTextAreacnt(0);
				if(fwRunning) {
					fwRunning = false;
					if(HttpPost.t != null)		// to avoid NPE
						HttpPost.t.cancel();					
				}
				if(fwpwRunning || digpwRunning) {
					fwpwRunning = false;
					digpwRunning = false;
					if(SetPassword.t != null)
						SetPassword.t.cancel();
				}
//				updateTextArea("Wait "+textField_period.getText() +" seconds...\n");
			}
		});
		SecurityTest.getContentPane().add(btnReset);
		
		JLabel lblNumberOfTimes = new JLabel("Cnt of succ oper:");
		lblNumberOfTimes.setBounds(10, 117, 121, 22);
		SecurityTest.getContentPane().add(lblNumberOfTimes);
		
		JLabel lblFwPw = new JLabel("FwPW");
		lblFwPw.setBounds(10, 37, 40, 22);
		SecurityTest.getContentPane().add(lblFwPw);
		
		textField_FwPw = new JTextField();
		textField_FwPw.setBounds(54, 38, 155, 20);
		textField_FwPw.setText("01234567890123456789");
		textField_FwPw.setColumns(10);
		SecurityTest.getContentPane().add(textField_FwPw);

		JLabel lblFw = new JLabel("FW");
		lblFw.setBounds(10, 65, 40, 22);
		SecurityTest.getContentPane().add(lblFw);
		
		textField_fw = new JTextField();
		textField_fw.setBounds(54, 66, 155, 20);
		textField_fw.setText("D:\\IEC61850_81.pck");
		textField_fw.setColumns(10);
		SecurityTest.getContentPane().add(textField_fw);
		
		JButton btnUpldfw = new JButton("UpldFW");
		btnUpldfw.setBounds(219, 63, 86, 23);
		btnUpldfw.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if((!fwpwRunning)&&(!digpwRunning)&&(!fwRunning)){
					debug = false;
					fwRunning = true;
					prepare_upldFW();
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
					if(period < 60){
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
					updateTextArea("Naughty guy! The operation is already in progress!! \n");
				}
			}
		});
		SecurityTest.getContentPane().add(btnUpldfw);
		
		JButton btnCert = new JButton("ChkCert");
		btnCert.setBounds(219, 11, 86, 23);
		btnCert.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
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
				GetCertificate.checkCert();						
			}
		});
		SecurityTest.getContentPane().add(btnCert);
		
		JButton btnExit = new JButton("Exit");
		btnExit.setBounds(307, 11, 65, 23);
		btnExit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		SecurityTest.getContentPane().add(btnExit);		
		
//		JTextArea
		textArea_cnt = new JTextArea();
		textArea_cnt.setBounds(169, 119, 40, 18);
		textArea_cnt.setText("0");
		SecurityTest.getContentPane().add(textArea_cnt);
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
	
	/**
	 * 识别输入的IP, PERIOD, 老密码.
	 * 密码后加五个星(*****)输出Log.
	 */
	public static void prepare_setFwPW(){
		String str;
		int len;
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
	
	/**
	 * 识别输入的IP, PERIOD, 老密码.
	 * 密码后加五个星(*****)输出Log.
	 */
	public static void prepare_setDigPW(){
		String str;
		int len;
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
	
	/**
	 * 识别输入的IP, PERIOD, FW 路径.
	 * 路径后加一个星(*),输出Log.
	 */
	public static void prepare_upldFW(){
		String str;		
		int len;
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
		if(str.indexOf("https") == -1) {
			if(str.matches("[a-zA-Z]+")) {
				ForFun = true;
				ip = "https://www."+str+".com";
			}else{
				ForFun = false;
				ip = str;
				period = Integer.parseInt(textField_period.getText());
				if (period == 99)
					debug = true;			
			}
		}		
//		if(str.indexOf("https") > -1) {
		else {
			ForFun = true;
			ip = str;
		}
	}
}
