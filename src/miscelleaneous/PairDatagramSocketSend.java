package miscelleaneous;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class PairDatagramSocketSend {
    /**
     * 此程序在172.20.1.1上作为发送方且接收返回数据，测试通过。接收方: 172.20.1.2:50000
     * @param args
     */
    public static void main(String[] args){
        try {
            // 创建发送方的套接字，IP默认为本地，端口号随机  
            DatagramSocket sendSocket = new DatagramSocket();
            String mes = "Hello receiver";
            byte[] buf = mes.getBytes();
            
            //确定对方的端口和IP. 即使端口错了,也会发送,但在wireshark里能看到Destination unreachable (Port unreachable)
            int port = 50000;
            InetAddress local = InetAddress.getByName("172.20.1.2");
            
            //创建发送类型的数据报,并通过udp 套接字发送.
            DatagramPacket sendPacket = new DatagramPacket(buf,buf.length,local,port);
            sendSocket.send(sendPacket);
            
            //创建接收型的数据报,并通过套接字接收
            byte[] messReturn = new byte[1024];
            DatagramPacket returnPacket = new DatagramPacket(messReturn,messReturn.length);
            sendSocket.receive(returnPacket);
            
            //解析
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
