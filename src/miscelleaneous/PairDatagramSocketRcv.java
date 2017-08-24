package miscelleaneous;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class PairDatagramSocketRcv {
	
	/**
	 * InetAddress �ĸ�ʽ��/172.20.1.1
	 * SocketAddress �ĸ�ʽ�� /172.20.1.1:56033
	 * DatagramPacket��ʾ������ݵ����ݱ���DatagramSocket��ʾ���ܻ������ݱ����׽��֣����ֿͻ��˻������������TCP��
	 * Ŀ�Ķ˿ں�IP�ڷ��ͷ������ݱ���������׽����ﶨ�塣�����ݱ��Ĺ��캯�����InetAddress��SocketAddress�ģ��������ڷ��͵ģ������������ڽ��յģ��׽���
	 * ֻ���ڰ󶨱����Ķ˿ڻ��IPʱ������ĳ��IP��
	 * �����Է���ַ�˿ڵ���Ϣʱ��Ҫ�����ݱ�������������Ǵ��׽�������籾���ж��ô�2�ģ�peerAddress2��peerSocketAddress2��port2������2�ģ�Ҫ�ȵ���connect()
	 * �������ܶ���ֵ��������null��-1�������ӵ�UDP�׽���������connect()�������������ã�����׽���ֻ�ܷ��͸�connect()����ָ���ĵ�ַ�����Ҵ�ʱ�����ݱ���ĵ�ַ������connect()
	 * �������һ�£����߷�����Ϣʱ���ݱ��ﲻ��Ҫָ����ַ�ˡ�-->����connect()��������ǳ��ģ�û���ԡ�������null,-1����ġ�
	 * @param args
	 */
	
	public static void main(String[] args) {
		try {
			InetAddress local = InetAddress.getByName("172.20.1.2");
			DatagramSocket rcvSocket = new DatagramSocket(50000,local);//�ڶ���������ѡ��������������IPʱ�á�
			byte[] buf = new byte[1024];
			DatagramPacket rcvPacket = new DatagramPacket(buf,buf.length); //�����������͵����ݱ����ŵ�buf�С�
			rcvSocket.receive(rcvPacket);	//ͨ��udp �׽��ֽ��ա�
			
			// �������ͷ����ݵ���Ϣ������ӡ
			String getMes = new String(buf,0,rcvPacket.getLength());
			String getMes1 = new String(rcvPacket.getData(),0,rcvPacket.getLength());
			System.out.println("Message from peer��" + getMes);
			
			// ͨ�����ݱ� �� udp �׽��ֵõ����ͷ���IP���׽��ֺͶ˿ںţ�����ӡ 
			InetAddress peerAddress = rcvSocket.getInetAddress();
			InetAddress peerAddress2 = rcvPacket.getAddress();
			SocketAddress peerSocketAddress = rcvSocket.getRemoteSocketAddress();
			SocketAddress peerSocketAddress2 = rcvPacket.getSocketAddress();
			int port = rcvSocket.getPort();
			int port2 = rcvPacket.getPort();
			System.out.println("peer IP��" + peerAddress2.getHostAddress());   //�����getHostAddress()��InetAddress��һ���������õ�IP��ַ�������Ƕ�Ӧ��socket�е�host.
            System.out.println("peer port��" + port2);  
			
            // ȷ��Ҫ�������ͷ�����Ϣ���ݣ���ת��Ϊ�ֽ�����  
            String feedback = "Received successfully";  
            byte[] backbuf = feedback.getBytes(); 
            
            //����. ���͵�udp ���ݰ����췽������ָ���Է��ĵ�ַ��
            DatagramPacket sendPacket = new DatagramPacket(backbuf,0,backbuf.length,peerSocketAddress2);
            rcvSocket.send(sendPacket);
            
            rcvSocket.close();
			
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
