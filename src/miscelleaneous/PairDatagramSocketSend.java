package miscelleaneous;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class PairDatagramSocketSend {
	/**
	 * �˳�����172.20.1.1����Ϊ���ͷ��ҽ��շ������ݣ�����ͨ�������շ�: 172.20.1.2:50000
	 * @param args
	 */
	public static void main(String[] args){
		try {
			// �������ͷ����׽��֣�IPĬ��Ϊ���أ��˿ں����  
			DatagramSocket sendSocket = new DatagramSocket();
			String mes = "Hello receiver";
			byte[] buf = mes.getBytes();
			
			//ȷ���Է��Ķ˿ں�IP. ��ʹ�˿ڴ���,Ҳ�ᷢ��,����wireshark���ܿ���Destination unreachable (Port unreachable)
			int port = 50000;
			InetAddress local = InetAddress.getByName("172.20.1.2");
			
			//�����������͵����ݱ�,��ͨ��udp �׽��ַ���.
			DatagramPacket sendPacket = new DatagramPacket(buf,buf.length,local,port);
			sendSocket.send(sendPacket);
			
			//���������͵����ݱ�,��ͨ���׽��ֽ���
			byte[] messReturn = new byte[1024];
			DatagramPacket returnPacket = new DatagramPacket(messReturn,messReturn.length);
			sendSocket.receive(returnPacket);
			
			//����
			String returned = new String(messReturn,0,returnPacket.getLength());
			System.out.println("Returned message: " + returned);
			
			sendSocket.close();
			
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}		
	}
}
