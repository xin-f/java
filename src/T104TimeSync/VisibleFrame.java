package T104TimeSync;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.ActionEvent;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JCheckBox;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JMenu;

/**
  * ����MouseListener�������,û����.....
  */
class MyMouse extends JFrame implements MouseListener {	//�������ʱ�����java.awt.event.MouseAdapter, ��ֻ��дҪ�õķ���.
														//MouseListener����д���г�Ա����,�籾��,��ʹû�õ�,ҲҪ�и��պ�����.
	 
	MyMouse(){
	System.out.println("mouse not cli");}
	 public void mouseClicked(MouseEvent e)    //���,���滹�ɼ�������������м�  
     {
		 System.out.println("mouse clicked");
     }
	 public void mouseEntered(MouseEvent e)   //���������  
     {}  
      
     public void mouseExited(MouseEvent e)     //����뿪���  
     {}  
      
     public void mousePressed(MouseEvent e)   //��걻����  
     {}  
      
     public void mouseReleased(MouseEvent e)   //��걻�ſ�  
     {}  
}

public class VisibleFrame {
	public static int port;
	public static int comaddr;
	public static String host = null;
	public static VisibleFrame window;
	public static Object[] TX_TIME_SELECTED;
	public static String SetTime;
	public static Timer timer = new Timer();
	public static String displayedTime;
	public static boolean chkbx_SetTime = false;
	private static JFrame frame;
	private JTextField TX_IP;
	private JTextField TX_PORT;
	private JTextField TX_TIME;
	private static JTextArea teleArea;
	private static JButton btnClear;
	private JTextField TX_COMADDR;//JTextField ���͵ı���Ĭ����static, Ҫȥ��static���ܱ���static�͵ĺ���initialize()����
	
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					window = new VisibleFrame();	//������ʵ��,������Ĺ��캯��,������ֻ��һ�д���initialize();�ĺ���.
					buildTextArea();
			//		updateTextArea();
					VisibleFrame.frame.setVisible(true);
					timerUpdating(timer);
					
					
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public VisibleFrame() {		
		initialize();
	}
	
	/**
	 * convert the string value TX_PORT to int
	 */
	public static int convertStringtoint(String str){
		return Integer.parseInt(str);		
	}
	
	/**
	 * A timer to update the TIME displayed cyclically.
	 */
	public static void timerUpdating(Timer t){
		t.scheduleAtFixedRate(new TimerTask(){
			public void run(){
				TimeHandling.getTime();
				window.TX_TIME.setText(TimeHandling.CUR_TIME);
			}
		}, 100, 1000);
	//	System.out.println("timer updating");
	}
	
	/**
	 * ֹͣtextField���ʱ�����,�Ա��ֶ��޸�ʱ��.
	 */
	public static void timeCancel(Timer t) {  
        t.cancel(); 
   //   System.out.println("timer canneled");
    }  
	
	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame("T104 Time Sync");
		frame.setBounds(100, 100, 480, 450);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		
		JLabel lblIp = new JLabel("IP");
		lblIp.setBounds(10, 11, 28, 14);
		frame.getContentPane().add(lblIp);
		
		TX_IP = new JTextField();
		TX_IP.setText("172.20.1.60");
		TX_IP.setColumns(10);
		TX_IP.setBounds(10, 27, 97, 21);
		frame.getContentPane().add(TX_IP);
		
		JLabel lblPort = new JLabel("Port");
		lblPort.setBounds(112, 11, 28, 14);
		frame.getContentPane().add(lblPort);
		
		TX_PORT = new JTextField();
		TX_PORT.setText("2404");
		TX_PORT.setColumns(10);
		TX_PORT.setBounds(112, 27, 34, 21);
		frame.getContentPane().add(TX_PORT);
		
		JLabel lblComadd = new JLabel("ComAd");
		lblComadd.setBounds(150, 11, 40, 14);
		frame.getContentPane().add(lblComadd);	
		
		TX_COMADDR = new JTextField();
		TX_COMADDR.setText("1");
		TX_COMADDR.setColumns(10);
		TX_COMADDR.setBounds(148, 27, 42, 21);
		frame.getContentPane().add(TX_COMADDR);		
		
		TX_TIME = new JTextField();
		TX_TIME.setBounds(10, 51, 136, 21);
		frame.getContentPane().add(TX_TIME);
		TX_TIME.setColumns(10);
		
		btnClear = new JButton("Clear");
		btnClear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				VisibleFrame.teleArea.setText("");
			}
		});
		btnClear.setBounds(192, 50, 69, 23);
		frame.getContentPane().add(btnClear);
		
		JButton btnSend = new JButton("Send");
		btnSend.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				displayedTime = window.TX_TIME.getText();	//ȡJTextField ��ʾ��ʱ��, ��SetTime��ѡ��ѡ��ʱ����ʱ��Դ��װ�ö�ʱ.
				port = convertStringtoint(window.TX_PORT.getText());
				comaddr = convertStringtoint(window.TX_COMADDR.getText());
				host = window.TX_IP.getText();
				Main.timeSync();
			
			
				
			}
		});
		btnSend.setBounds(192, 23, 69, 23);
		frame.getContentPane().add(btnSend);
		
		/**
		 * introduce this CheckBox to 'froze' the time cyclic updating so that the Time in TextField can be changed then used as time source	 
		 */
		JCheckBox chkbxSetTime = new JCheckBox("Set Time");
		chkbxSetTime.setBounds(10, 78, 82, 21);
		frame.getContentPane().add(chkbxSetTime);
		
		final JFrame j=new JFrame();
		JMenuBar menuBar = new JMenuBar();
		frame.setJMenuBar(menuBar);
		
		JMenu mnHelp = new JMenu("Help");
		menuBar.add(mnHelp);
		JMenuItem About = new JMenuItem("About"); 
		mnHelp.add(About);	//Ҫ�ֶ�����add()������MenuItem��Menu��?
		
		ActionListener al =new ActionListener(){
			   public void actionPerformed(ActionEvent e) {
			       String buttonString=e.getActionCommand();	
				if(buttonString.equals("About"))
				JOptionPane.showMessageDialog(j, 	"This is an immature but maybe helpful widget for T104\n"
						+ 		"time synchronization test. Your suggestion is warmly\n"
						+ 		"welcome although maybe it will not be treated.");
				}
			};
		About.addActionListener(al);
		j.setBounds(180, 300, 300, 100);	
		j.setDefaultCloseOperation (JFrame.EXIT_ON_CLOSE);
//		j.setVisible(true);
		
		chkbxSetTime.addItemListener(new ItemListener(){
			public void itemStateChanged(ItemEvent e){				
		         TX_TIME_SELECTED = chkbxSetTime.getSelectedObjects();
		         SetTime = (TX_TIME_SELECTED == null)?"Check box is not selected":TX_TIME_SELECTED[0].toString();
		//         System.out.println(SetTime);
		         if(!(SetTime.equals("Set Time"))){
						timerUpdating(timer);
						chkbx_SetTime = false;
				//		System.out.println(chkbx_SetTime);
					}
		         else{
		        	 timeCancel(timer);
		        	 timer = new Timer();	//�Ӱ�!!�Ѿ���cancel����Timer��������������, ����Ҫ����new һ��.
		        	 chkbx_SetTime = true;
		      //  	 System.out.println(chkbx_SetTime);
					}
		    }
		});	//������ѡ�����.				
	}
	
	/**
	 * ����TextArea. ֮���Ե�����һ����������TextArea������������updateTextArea()�������ڸ���ǰ����,����Ϊ������ºʹ�����
	 * ͬһ��������,ÿ�θ���ʱ,TextArea�������´���,ԭ����ʾ����Ϣ��û��, ����ȥ�͸�û����һ��.
	 */
	public static void buildTextArea() { 
		teleArea = new JTextArea();
	//	teleArea.setBounds(10, 126, 414, 126);
	//	frame.getContentPane().add(teleArea);
		JScrollPane js=new JScrollPane(teleArea);//Ҫ��JTextArea�ӵ�JScrollPane����,�Ż��й���������.JScrollPane�ĳߴ���λ�ó�ǰ��JTextArea�Զ����ɵ�
		js.setBounds(15, 126, 435, 270);
		frame.getContentPane().add(js);
	//	js.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED); /��֪��Ϊʲô���ܼ�������??
	//	js.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		js.setVisible(true);
		
    }  

	/**
	 * ����TextArea,��ʾ�������ݼ�����. ��������������÷�����������ǰ��initialize()�ﴴ��,��Ϊ���ñ���������.������������?
	 */
	public static void updateTextArea(String str) { 
		teleArea.append(str);
    }  
}




