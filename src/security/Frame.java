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

	private static JFrame frmFwUpdatingAnd;
	private static JTextArea textArea;
	private static JTextArea textArea_cnt;
	private static JTextField textField_ip;
	private JLabel PERIOD;
	private static JTextField textField_period;
	private static JTextField textField_curpw;
	private static JTextField txtDsecurityTesttestversion;
	
	public static String ip;
	public static int period;
	public static String curpw;
	public static String fw;
	public static boolean pwRunning; //password is being set. To disturb the pw setting when 'Reset'
	public static boolean fwRunning; //fw is being uploaded. To disturb the fw uploading when 'Reset'
	public static boolean debug;
	
	static File file = null;
	static PrintStream logStream = null;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Frame window = new Frame();					
					buildTextArea();
					window.frmFwUpdatingAnd.setVisible(true);
															
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
		frmFwUpdatingAnd = new JFrame();
		frmFwUpdatingAnd.setTitle("FW updating and PW setting");
		frmFwUpdatingAnd.setBounds(100, 100, 398, 327);
		frmFwUpdatingAnd.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmFwUpdatingAnd.getContentPane().setLayout(null);
		
		JLabel IPADDR = new JLabel("IP");
		IPADDR.setBounds(10, 11, 17, 22);
		frmFwUpdatingAnd.getContentPane().add(IPADDR);
		
		textField_ip = new JTextField();
		textField_ip.setText("172.20.1.24");
		textField_ip.setBounds(26, 12, 86, 20);
		frmFwUpdatingAnd.getContentPane().add(textField_ip);
		textField_ip.setColumns(10);
		
		PERIOD = new JLabel("PERIOD(S)");
		PERIOD.setBounds(122, 15, 64, 14);
		frmFwUpdatingAnd.getContentPane().add(PERIOD);
		
		textField_period = new JTextField();
		textField_period.setText("20");
		textField_period.setBounds(183, 12, 26, 20);
		frmFwUpdatingAnd.getContentPane().add(textField_period);
		textField_period.setColumns(10);
		
		JButton btnSetPW = new JButton("SetPW");
		btnSetPW.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(!fwRunning){
					debug = false;
					pwRunning = true;
					prepare_setPW();
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
					if(period < 15){
						updateTextArea("To avoid timeout, set the period no less than 15s.\n");
					}else{
						SetPassword.set();
					}
				}else{
					updateTextArea("FW uploading is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}				
			}
		});
		btnSetPW.setBounds(219, 37, 86, 23);
		frmFwUpdatingAnd.getContentPane().add(btnSetPW);
		
		JButton btnReset = new JButton("Reset");
		btnReset.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				SetPassword.succ = 0;
				HttpPost.suc = 0;
				textArea.setText("");
				updateTextAreacnt(0);
				if(fwRunning) {
					fwRunning = false;
					if(HttpPost.t != null)		// to avaoid NPE
						HttpPost.t.cancel();					
				}
				if(pwRunning) {
					pwRunning = false;
					if(SetPassword.t != null)
						SetPassword.t.cancel();
				}
				updateTextArea("Wait "+textField_period.getText() +" seconds...\n");
			}
		});
		btnReset.setBounds(219, 11, 86, 23);
		frmFwUpdatingAnd.getContentPane().add(btnReset);
		
		JLabel lblNumberOfTimes = new JLabel("Cnt of succ oper:");
		lblNumberOfTimes.setBounds(10, 87, 121, 22);
		frmFwUpdatingAnd.getContentPane().add(lblNumberOfTimes);
		
		JLabel lblCurrPw = new JLabel("CurPW");
		lblCurrPw.setBounds(10, 37, 40, 22);
		frmFwUpdatingAnd.getContentPane().add(lblCurrPw);
		
		textField_curpw = new JTextField();
		textField_curpw.setText("01234567890123456789");
		textField_curpw.setColumns(10);
		textField_curpw.setBounds(54, 38, 155, 20);
		frmFwUpdatingAnd.getContentPane().add(textField_curpw);

		JLabel lblFw = new JLabel("FW");
		lblFw.setBounds(10, 65, 40, 22);
		frmFwUpdatingAnd.getContentPane().add(lblFw);
		
		txtDsecurityTesttestversion = new JTextField();
		txtDsecurityTesttestversion.setText("D:\\Security test\\TestVersion\\IEC61850_81_June21_2.pck");
		txtDsecurityTesttestversion.setColumns(10);
		txtDsecurityTesttestversion.setBounds(54, 66, 155, 20);
		frmFwUpdatingAnd.getContentPane().add(txtDsecurityTesttestversion);
		
		JButton btnUpldfw = new JButton("UpldFW");
		btnUpldfw.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(!pwRunning){
					debug = false;
					fwRunning = true;
					prepare_upldFW();
					if(debug){
						file = new File("log.txt");
						try {
							logStream = new PrintStream(new FileOutputStream(file));
						} catch (FileNotFoundException e1) {
							// TODO Auto-generated catch block
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
				else{
					updateTextArea("PW setting is in progress!! \n"
							+ "Click 'Reset', wait "+textField_period.getText() +" seconds and try again.\n");
				}
			}
		});
		btnUpldfw.setBounds(219, 65, 86, 23);
		frmFwUpdatingAnd.getContentPane().add(btnUpldfw);

		JButton btnExit = new JButton("Exit");
		btnExit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		btnExit.setBounds(307, 11, 65, 23);
		frmFwUpdatingAnd.getContentPane().add(btnExit);		
		
//		JTextArea
		textArea_cnt = new JTextArea();
		textArea_cnt.setText("0");
		textArea_cnt.setBounds(169, 91, 40, 18);
		frmFwUpdatingAnd.getContentPane().add(textArea_cnt);
	}
	
	private static void buildTextArea(){
		textArea = new JTextArea();
//		textArea.setBounds(10, 90, 275, 161);
//		frame.getContentPane().add(textArea);
		JScrollPane js=new JScrollPane(textArea);//要把JTextArea加到JScrollPane里面,才会有滚动条出来.JScrollPane的尺寸与位置抄前面JTextArea自动生成的
		js.setBounds(10, 110, 275, 170);
		frmFwUpdatingAnd.getContentPane().add(js);	
		DefaultCaret caret = (DefaultCaret) textArea.getCaret(); // 这两行让文本框的滚动条自动在最下面.
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
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
	public static void prepare_setPW(){
		String str;
		int len;
		ip = textField_ip.getText();
		period = Integer.parseInt(textField_period.getText());
		str = textField_curpw.getText();
		len = str.length();
		if(str.endsWith("*****")){
			debug = true;
			curpw = str.substring(0, len - 5);
		}
		else curpw = str;
	}
	/**
	 * 识别输入的IP, PERIOD, FW 路径.
	 * 路径后加一个星(*),输出Log.
	 */
	public static void prepare_upldFW(){
		String str;		
		int len;
		ip = textField_ip.getText();
		period = Integer.parseInt(textField_period.getText());
		str = txtDsecurityTesttestversion.getText();
		len = str.length();
		if (str.endsWith("*")){
			fw = str.substring(0, len - 1);
			debug = true;
		}else
			fw =str;
		curpw = textField_curpw.getText();		
	}
}
