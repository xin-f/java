package T104TimeSync;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.*;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

public class Main {
 

    public static int LEN = 0;
    public static int NS = 0;
    public static int NR = 0;
    public static int cnt = 0;
    public static int total = 0;
    public static boolean STDreceived = false; //STARTDT con received
    public static boolean TSreceived = false;	//time sync con received
     
    /**
     * read()�������ڵ�ѭ��,���������������Ǽ��������ֽ���,��cnt < in.available() ��������ʱ����,��������,����������..
     */
    public static void timeSync() {    
            Socket socket = null;
			try {				
			//	socket = new Socket(Setting.IP_ADDR, Setting.PORT);    //����socket����.�������ó�ʱʱ��,���Ը������������.
				socket =  new Socket();
				try{
				socket.connect(new InetSocketAddress(VisibleFrame.host, VisibleFrame.port), 1000);
//    			socket.setSoTimeout(500); //�뿿�Ӹ�timeout ����read()���������в�ͨ��,timeout��ʱ���ֱ�ӹر�socket connection.
				}catch(SocketTimeoutException timeout){
					String tmp = timeout.toString();
					int a = tmp.indexOf(":");
					VisibleFrame.updateTextArea(tmp.substring(a+1)+"\n");					
				}
				DataInputStream in = new DataInputStream(socket.getInputStream()); 
//                BufferedInputStream bin = new BufferedInputStream(in);
       //       BufferedReader input =new BufferedReader(new InputStreamReader(in));
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());    
                byte[] boStartDT = HexStrToByte.hexStringToBytes(Setting.STARTDT);
                out.write(boStartDT);
                out.flush();
                VisibleFrame.updateTextArea(Setting.STARTDT+"  STARTDT ACT"+"\n");                 
                byte[] biStartDT = new byte[Setting.len_US];
                in.read(biStartDT);
//                Thread.sleep(10);  //�߳�sleep��,������,server����������Ȼ��д����������,��˯���˾ͻ��.
                String str = "";
                str = T104TimeSync.ByteToStr.byteToStr(biStartDT);                               
                TelegramClassify.distgUIS(str);
                if(TelegramClassify.isU = false){
                	VisibleFrame.updateTextArea("Not U format received. STARTDT failed");
                }
                if(!(str.substring(5, 6).equals("b") || str.substring(5, 6).equals("B"))){
                	 VisibleFrame.updateTextArea("STARTDT failed");                	
                }else{
                	VisibleFrame.updateTextArea("   "+str+"  STARTDT CON"+"\n"); 
                	STDreceived = true;                
                    Setting.TIMESYNC = TimeFraming.framing();                
	                byte[] boTimeSync = HexStrToByte.hexStringToBytes(Setting.TIMESYNC);
	                out.write(boTimeSync);
	                out.flush(); 
//	                Thread.sleep(10); //
	                VisibleFrame.updateTextArea(Setting.TIMESYNC.toUpperCase()+"\n");
	                VisibleFrame.updateTextArea(TimeParsing.parsing(Setting.TIMESYNC.toUpperCase())+"\n");
	/*                byte[] biTimeSync = new byte[2048];			//�㹻����������װ������һ�ѱ���, Ȼ���ٸ���68�ͺ���ĳ��ȷָ�ɶ�֡.
	                bin.read(biTimeSync);
	                str = t104.ByteToStr.byteToStr(biTimeSync);
	                String[] bi = new String[11]; 
	                for (int i = 0; i<11;i++){bi[i] = null;}
	                bi = SplitTele.splitTele(str);
	                for(int i = 0; i<11; i++){
	                	if(bi[i] != null){
	                	if( bi[i].substring(12,14).equals("67") ){
	                	   System.out.println(bi[i]);
	                	   Treceived = true;
	                	   VisibleFrame.updateTextArea("   "+bi[i]+"\n");
	                	   VisibleFrame.updateTextArea("   "+TimeParsing.parsing(bi[i])+"\n");
	                	   }
	                	}
	                }
	                if(Treceived == false){
	                	VisibleFrame.updateTextArea("   No time synchronization response received."+"\n");
	                	System.out.println("no Treceived");
	               // 	System.exit(0);
	                }
	*/
	                cnt = 0;
	                TSreceived = false;	
	                total = 0;
//	                total = in.available();
	                while((total = in.available()) == 0){
	                	Timer t = new Timer();	                	 
	                	t.schedule(new TimerTask(){		                		
	                		public void run(){
//	                			System.out.println("I'm waiting: ");
	                		}		                		
	                	}, 0,100);	
	                //��100ms��һ��,ֱ��������������������,��in.available()��Ϊ0. ����ֻ��һ��,
	                //����t.schedule(new TimeTask(){},long);break;����һ������,��longʱ�������һ��,break����
	                }
	                System.out.println("total "+total);
	                while(cnt < total){ 
	                    byte[] biTS = so(in);
	                    str = T104TimeSync.ByteToStr.byteToStr(biTS);
	                    System.out.println(str);
	                    if(str.substring(12, 14).equals("67")){                    	
	                    	TSreceived = true;
	                    	VisibleFrame.updateTextArea("   "+str+"\n");
	                    	VisibleFrame.updateTextArea("   "+TimeParsing.parsing(str)+"\n");
	                    }
	                }
	                if(TSreceived == false){
	                	VisibleFrame.updateTextArea("   No time sync con received for this request. "+"\n");
	                	System.out.println("no TSreceived");
	                }
	                else{ //��������else{}��,�и�������,�����һ����Ӧ�ı�����û�ж�ʱ,��û��,����STOPDT����������.
	                	byte[] boSuper = HexStrToByte.hexStringToBytes(Setting.SUPERVISORY);
	                    out.write(boSuper);
	                    out.flush();
	                    VisibleFrame.updateTextArea(Setting.SUPERVISORY+"  SUPERVISORY"+"\n");
	                   	                
		                byte[] boStopDT = HexStrToByte.hexStringToBytes(Setting.STOPDT);
		                out.write(boStopDT);
		                out.flush();
		                VisibleFrame.updateTextArea(Setting.STOPDT+"  STOPDT ACT"+"\n");
		//                Thread.sleep(10);	  
		                cnt = 0;
		                total = 0;
		                total = in.available();
		                while((total = in.available()) == 0){
		                	Timer t = new Timer();	                	 
		                	t.schedule(new TimerTask(){		                		
		                		public void run(){
	//	                			System.out.println("I'm waiting: ");
		                		}		                		
		                	}, 10,500);	// �����һ��break;, ��ֻ��500ms������ѭ��. ��ͬ��ǰ���server�����ı�ʱ��Ӧ����.
	//	                	break;
		                }
		                System.out.println("total after stopDT: "+total);
		                while(cnt < total ){ 
		                    byte[] biStopDT = so(in);
		                    str = T104TimeSync.ByteToStr.byteToStr(biStopDT);
		                    System.out.println(str);
		                    if(!(str.substring(4, 5).equals("2") )){
		                        System.out.println("STOPDT failed");
		                        if((str.length()>12)&&(str.substring(12,14).equals("67")) ){
		                        VisibleFrame.updateTextArea("  "+str+"\n");
		                        VisibleFrame.updateTextArea("   "+TimeParsing.parsing(str)+"\n");
		                        }//�������STOPDT֮������һ֡ʱ�ӱ���.
		                        }else{
		                        	VisibleFrame.updateTextArea("   "+str);
		                        	VisibleFrame.updateTextArea("   STOPDT CON"+"\n");                	
		                        }
		                }
	                } //TSreceived == true ends here.	                
                } // STARTDT = true  ends here.
                out.close();  
//                bin.close();
                in.close();
            } catch (Exception e) {  
                System.out.println(e.getMessage());   
            } finally {  
                if (socket != null) {  
                    try {  
                        socket.close();  
                       // System.out.println("socket is closed");  
                    } catch (IOException e) {  
                        socket = null;   
                        System.out.println(e.getMessage());   
                    }  
                }  
            }            
    } 
    public static byte[] so(DataInputStream in) throws IOException{
    	
    	int start = 0;
    	start = in.read();
//        do
//        {
//            start = in.read();
//        } while (start != 0x68);
//        if (start == -1)
//            throw new EOFException();
    	
    //	if((in.read()) == 0x68){
	        int length = in.readUnsignedByte();
	        byte[] message = new byte[length+2];
	        message[0]=(byte)0x68;message[1] = (byte)length;
	        in.readFully(message,2,length);
	        cnt += (length+2);
	        return message;
	 //   }
    }

}

