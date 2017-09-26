package redundancy_client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Timer;
import java.util.TimerTask;

public class Main { 

			
	public  void multiClient(String clientIP, String clientPORT) throws UnknownHostException{
		WebAccess w = new WebAccess(InetAddress.getByName(MultCli.ServerIP),2404, InetAddress.getByName(clientIP),Integer.parseInt(clientPORT));
//		WebAccess w2 = new WebAccess(InetAddress.getByName("172.20.1.60"),2404, InetAddress.getByName("172.20.1.3"),10001);
//		t1 = new Thread(w);
//		t2 = new Thread(w2);
//		t1.start();
//		t2.start();
	}		
}
class WebAccess implements Runnable{
	int dstport;
	int localport;
	InetAddress dst = null;
	InetAddress local = null;
	WebAccess(InetAddress host, int hostport,InetAddress client, int clientport){ //���캯��
		dst = host;	
		local = client;
		dstport = hostport;
		localport = clientport;
	}	
	Socket socket = null;
	String STARTDT = "680407000000";
	String TESTFR = "680443000000";
	String TESTFRCON = "680483000000";
	String GI = "680E0200000064010600010000000014"; //�������еķ������к�Ϊ 1
	String supervisory = null;
	String str = null;
	static int nr;	//�ͻ��˽��պ�,�յ�I֡ʱ��1,TCP����ʱ����. ����Ҫ��volatile��? 
	int ns = 0; //�ͻ��˷��ͺ�
	int total = 0; 
	boolean startDTCON = false;
	volatile boolean stop = false;	//����������ʱ��
	boolean getSpon = false; //�յ�ͻ����Ϣ,������ S ֡.
	boolean recvTestFR = false; 
	public static Timer timer = null;
//	public static String name = null;
	DataInputStream in = null;
	DataOutputStream out = null;

	
	public void run(){
		try {
			initialize();
		} catch (IOException e) {
			e.printStackTrace();
		}		
		
		SendTestFR sendTestFR = new SendTestFR();
//		Thread t = new Thread(sendTestFR);
//		t.start();	//������,�Ѿ���һ��TimerTask,��timer.schedule��.
		timer = new Timer();
		if(startDTCON == true)
		timer.schedule(sendTestFR, 0, /*MultCli.T3 *1000*/5000);
	}
	
	class Listen extends Thread{		
		Listen(String str){
			Thread.currentThread().setName(str);
		}
		Listen(){}
		public void run(){
			int start;
			boolean hasI = false;
				try {
					if((start = in.read()) == 0x68){
						System.out.println("start: "+start);
						int len = in.read();
						byte[] tmp = new byte [len];
						in.readFully(tmp);
						if(len == 4) {
							recvTestFR = true; //�յ�����֡. 
							MultCli.updateTextArea(MultCli.threadName+": Recv TESTFR ACT\n");
							System.out.println(MultCli.threadName+": Recv TESTFR ACT");
							sendTestFRCON();
						}
						else{
							nr += 2;								
							hasI = true; //�յ�I ֡,while()���жϺ�ȷ��.
						}
					}
				} catch (IOException e) {
					System.out.println("Exception is not printed here, but there's interupption.");
					//e.printStackTrace();
				}
//			}
			if(hasI == true){
				try {
					sendS(socket);
					hasI = false;
				} catch (IOException e) {
					e.printStackTrace();
				} //����ÿһ��I֡������ȷ��,�п��ܼ�����һ��packet��.
			}
		}
	}
	
	class SendTestFR extends TimerTask{
		String str1;
		SendTestFR(String abc){
			System.out.println("New SendTestFR Object created ");
			str1 = abc;
		}
		SendTestFR(){} //constractor
		public void run(){	
			Listen listen = new Listen();
			listen.start();
			Timer t1_server = new Timer(true); //��ʼ����,��S֡ȷ����������Ӧ��,������ʱ����,������ʱ��û�յ�����,�ͷ�Test FR.		
			t1_server.schedule(new TimerTask(){ //û��,�������ܽ���DataInputStream.read()������.����setSoTimeout()
				public void run(){
//					listen.interrupt();
//					System.out.println("listen interrupt");
				}			
			}, /*MultCli.T1 *1000*/1000); //.		
		}
	}
	/**
	 * Create normal connection by send STARTDT and check response.
	 * @throws IOException 
	 * �����ȷ���ʱ,�ٷ�����.
	 * �����װ�÷���S֡�������Ƿ���ȷ.
	 */
	private boolean initialize() throws IOException {
		socket = new Socket(dst,dstport,local,localport);
		socket.setSoLinger(true, 1);
		socket.setSoTimeout(2000);
		in = new DataInputStream(socket.getInputStream());
		out = new DataOutputStream(socket.getOutputStream()); 
		byte[] boStartDT = HexStrToByte.hexStringToBytes(STARTDT);
		out.write(boStartDT);
        out.flush();
        nr = 0;
        byte[] biStartDT = new byte[6];
        in.read(biStartDT);
        str = ByteToStr.byteToStr(biStartDT);
        if(!(str.substring(5, 6).equals("b") || str.substring(5, 6).equals("B"))){        	
        	startDTCON = false;
        }else{
        	startDTCON = true;
        	byte[] boTS = StrToByte.strToByte(TimeFraming.framing());
        	out.write(boTS);
        	out.flush();
        	ns += 2;
        	try {
				Thread.sleep(800);
			} catch (InterruptedException e) {				
				e.printStackTrace();
			}
        	//��ʱ��Ӧ����ֻ������������������ nr .        	
        	sendS(nr, socket, in);
        	//����,ȷ�����ʱ��Ӧ֮�󵽷���GI֮ǰ,���ʱ��᲻����װ�õı�������?�еĻ�һֱbuffer������������?
        	byte[] boGI = StrToByte.strToByte(GI);
        	out.write(boGI);
        	out.flush();
        	System.out.println("GI send");
        	ns += 2;
        	/*try {
				Thread.sleep(600);
			} catch (InterruptedException e) {				
				e.printStackTrace();
			}*/
        	//������Ӧ���Ĳ�����.
//        	sendS(nr, socket, in); //�Ĵ�,�߳�˯1000ms Ҳ����֤������Ϣ���ͽ���!! �Ҳ�,�Ĵ�����Ӧ����,��󲻷�cot = 0x0a00, �͵�t1�󱨳�ʱ�ر�socket��.��
        	while(in.read()==0x68){
        		int len = in.readUnsignedByte();
        		if(len > 4) nr += 2;
        		byte[] tmp = new byte[len];	
        		in.readFully(tmp);
        		String str = ByteToStr.byteToStr(tmp);
        		if (str.substring(12, 16).equals("0a00") || str.substring(12, 16).equals("0A00")) 
        			break;  //һֱ�鵽���ٽ���,��֮ǰ������Է�,Ҳ��nr ��2,һ����S ȷ����. ��Ϊ�о��ǳ��ȴ���4.
        	}
        	/*String NR = Integer.toHexString(nr);
    		if (NR.length() == 1)
    			NR = "0" + NR;
    		String supervisory = "68040100" + NR + "00"; //������ս������кŲ�����127,��һ���ֽ���һ��bitҲ�ܱ�ʾ.
    		byte[] boSendS = StrToByte.strToByte(supervisory);
    		out.write(boSendS);
            out.flush();*/ 
        	sendS(socket);
        }
		return startDTCON;
	}
	
	
	private void sendS(Socket s) throws IOException{
		supervisory = "68040100";
//		nr = rcvnum;
    	if (nr >= 254){
    		System.out.println("Only one byte for N(s), 254 reached. Pls restart.");
    	}
    	String NR = Integer.toHexString(nr);
		if (NR.length() == 1)
			NR = "0" + NR;
		supervisory = supervisory + NR + "00"; //������ս������кŲ�����127,��һ���ֽ���һ��bitҲ�ܱ�ʾ.
		out = new DataOutputStream(s.getOutputStream()); 
		byte[] boSendS = StrToByte.strToByte(supervisory);
		out.write(boSendS);
        out.flush();  
	}
	/*
	 * �������к�̫���û����
	 */
	//68 len nsl nsh nrl nrh ti sq cotl coth addl addh 00 00 00 14
	private void sendS(int rcvnum, Socket s, DataInputStream in) throws IOException{
		supervisory = "68040100";
//		String tele = null;
		total = in.available();
//    	System.out.println("available: "+in.available());
    	int start = 0;
    	int len;
    	while ((start = in.read()) == 0x68){
    		len = in.readUnsignedByte();
//    		System.out.println("in sendS, len is (readUnsignedByte) "+len);
    		byte[] tmp = new byte[len];	//��ʱ������ձ���,��������.
    		in.readFully(tmp);
    		total = total - len - 2;
    		if(len > 4){	//���ȴ��� 1+1+4=6, I֡
    			rcvnum += 2;
    		}
    		/*���Է���Ϣ�����,ÿ�ζ���Sȷ��.���ö��Է���Ϣ��һ��packetʱ��ô��?*/
    		/*��:û��ϵ,��������ͨ��0x68������ͨ��һ��frame���ضϵ�*/
    		/*tele = "68" + Integer.toHexString(len) + ByteToStr.byteToStr(tmp);
    		if (tele.substring(16, 20).equals("0300")){ //cot = 03,�Է���Ϣ
    			getSpon = true;
    		}*/
//    		System.out.println("available in loop: "+ in.available());
    		if (total == 0) break; //����Ӧ��Ҳ����һ��initialize()����t_ListenSpon, Ȼ����cot = 0x0a����������.
    	}
    	nr = rcvnum;
    	if (nr >= 254){
    		System.out.println("Only one byte for N(s), 254 reached. Pls restart.");
    	}
    	String NR = Integer.toHexString(rcvnum);
		if (NR.length() == 1)
			NR = "0" + NR;
		supervisory = supervisory + NR + "00"; //������ս������кŲ�����127,��һ���ֽ���һ��bitҲ�ܱ�ʾ.
		out = new DataOutputStream(s.getOutputStream()); 
		byte[] boSendS = StrToByte.strToByte(supervisory);
		out.write(boSendS);
        out.flush();          
	}//sendS ����S֡����.
	
	private void sendTestFRACT() throws IOException{
		byte[] boTestFR = HexStrToByte.hexStringToBytes(TESTFR);
	    out.write(boTestFR);
        out.flush();        
        MultCli.updateTextArea(MultCli.threadName+": Send TESTFR ACT\n");
        System.out.println(MultCli.threadName+": Send TESTFR ACT");
	}
	private void sendTestFRCON() throws IOException{
		byte[] boTestFRCON = HexStrToByte.hexStringToBytes(TESTFRCON);
	    out.write(boTestFRCON);
        out.flush();
        MultCli.updateTextArea(MultCli.threadName+": Send TESTFR CON\n");
        System.out.println(MultCli.threadName+": Send TESTFR CON");
	}
	
	/*class ListenSpon implements Runnable{ //����������ͻ����Ϣ,������.
		DataInputStream in = null;
		int start;
    	int len;
    	String str = null;
		ListenSpon(DataInputStream dis){
			in = dis;
			System.out.println("new thread runs");
		}
		public void run(){
			try {
				//68 len nsl nsh nrl nrh ti sq cotl coth addl addh 00 00 00 14
				while ((start = in.read()) == 0x68){
					len = in.read();
					byte[] tmp = new byte[len];
					System.out.println("in listenspon, len is "+len);
					in.readFully(tmp);
					str = ByteToStr.byteToStr(tmp);
					if(str.length() > 16){
						if(str.subSequence(12, 16).equals("0300")){
							getSpon = true;
							nr += 2;
//							break; //ֻҪ������һ��ͻ���¼�,������.
						}
					}									
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}*/
}
/*5.16.2017 ֮ǰ���ʼ������һ���߳�������ͻ���¼�, ������ʵ�ֲ���. ����߳�����ñ��socket,�൱��һ������,����. ����ٽ�һ��socket, Ҫʵ��һ���׷�,�ղ���.
 * 			���뷨, ��SendTestFR ��ĳ�ʼ���м��β�,��DataInputStream in ������,�ж�����������û��ͻ���¼�(��������Ҳ��ֱ����ʵ������).
 *5.17.2017 �߳���һֱΪThread 17..֮�����������,�����߳�����ʾΪClient I,II,III,�ڴ���ʵ��ʱ������Thread.currentThread().setName(arg0)����ȥ,.getName()���,������
 *			�����MultCli�����߳�ʱ��t1.getName()����һ���ַ���,��ȡ����,�㶨.
 */
