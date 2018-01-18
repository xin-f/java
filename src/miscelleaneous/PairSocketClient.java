package miscelleaneous;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

public class PairSocketClient {
    static InputStream in;
    static OutputStream out;
    static String host = "172.20.1.1";
    /**
     * This code together with PairServer.java, shows how to re-use a socket and in/out stream instead of create a new one.
     *  1) In PairServer.java, server listen on 50000 port and if there's connection request, establish a socket.
     *  2) Client send telegram to Server. Server responds with different info accord to the telegram received from Client
     *  3) Client then re-use the stream and socket to send message to Server.
     *  
     *  往socket里写东西，要先把16进制数据转成byte[] 或byte, 然后发送。收到的数据要从byte[]转成String, int等可读的东西。
     * @param args
     */
    public static void main(String[] args) {
        
        try {
            Socket socket = new Socket(InetAddress.getByName(host),50000);
            /*如果指定timeout的socket，用以简单扫描某个TCP口是否打开，在构造socket时，要构造一个未连接到远程服务器的，
             * 以便能调用connect(SocketAddress endpoint, int timeout)方法。那就只能是Socket socket = new Socket(),无参数。
             * 然后在使用时再传进对端的SocketAddress,或其子类实例InetSocketAddress:
             * socket.connect(new InetSocketAddress(InetAddress.getByName(host),80), 1000);
             * InetAddress加port号组成InetSocketAddress.
             * */
            out = socket.getOutputStream();
            out.write(0x1);     //write 1 or 2 here.
            out.flush();
            in = socket.getInputStream();
            int i = 0;
            i = in.read();
            if(i == 0x61){
                out.write("xxx".getBytes());
                out.flush();
                System.out.println("\"a\" received, send \"xxx\"");
            }
            if(i == 0x62){
                out.write("yyy".getBytes());
                out.flush();
                System.out.println("\"b\" received, send \"yyy\"");
            }

        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
    }
}
