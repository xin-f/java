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
	 * InetAddress 的格式：/172.20.1.1
	 * SocketAddress 的格式： /172.20.1.1:56033
	 * DatagramPacket表示存放数据的数据报。DatagramSocket表示接受或发送数据报的套接字，不分客户端或服务器，不像TCP。
	 * 目的端口和IP在发送方的数据报里而不是套接字里定义。即数据报的构造函数里带InetAddress或SocketAddress的，都是用于发送的，不带都是用于接收的；套接字
	 * 只用于绑定本机的端口或多IP时的其中某个IP。
	 * 解析对方地址端口等信息时，要从数据报里解析，而不是从套接字里。比如本例中都用带2的，peerAddress2，peerSocketAddress2，port2。不带2的，要先调用connect()
	 * 方法才能读到值，否则是null或-1。无连接的UDP套接字有两个connect()方法，若被调用，则此套接字只能发送给connect()方法指定的地址，而且此时，数据报里的地址必须与connect()
	 * 方法里的一致，或者发送信息时数据报里不需要指明地址了。-->关于connect()方法这句是抄的，没测试。但返回null,-1是真的。
	 * @param args
	 */
	
	public static void main(String[] args) {
		try {
			InetAddress local = InetAddress.getByName("172.20.1.2");
			DatagramSocket rcvSocket = new DatagramSocket(50000,local);//第二个参数可选，本机多网卡多IP时用。
			byte[] buf = new byte[1024];
			DatagramPacket rcvPacket = new DatagramPacket(buf,buf.length); //创建接收类型的数据报，放到buf中。
			rcvSocket.receive(rcvPacket);	//通过udp 套接字接收。
			
			// 解析发送方传递的消息，并打印
			String getMes = new String(buf,0,rcvPacket.getLength());
			String getMes1 = new String(rcvPacket.getData(),0,rcvPacket.getLength());
			System.out.println("Message from peer：" + getMes);
			
			// 通过数据报 或 udp 套接字得到发送方的IP，套接字和端口号，并打印 
			InetAddress peerAddress = rcvSocket.getInetAddress();
			InetAddress peerAddress2 = rcvPacket.getAddress();
			SocketAddress peerSocketAddress = rcvSocket.getRemoteSocketAddress();
			SocketAddress peerSocketAddress2 = rcvPacket.getSocketAddress();
			int port = rcvSocket.getPort();
			int port2 = rcvPacket.getPort();
			System.out.println("peer IP：" + peerAddress2.getHostAddress());   //这里的getHostAddress()是InetAddress的一个方法，得到IP地址。并不是对应着socket中的host.
            System.out.println("peer port：" + port2);  
			
            // 确定要反馈发送方的消息内容，并转换为字节数组  
            String feedback = "Received successfully";  
            byte[] backbuf = feedback.getBytes(); 
            
            //回送. 发送的udp 数据包构造方法必须指定对方的地址。
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
