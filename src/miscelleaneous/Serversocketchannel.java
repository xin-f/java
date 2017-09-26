package miscelleaneous;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;

public class Serversocketchannel {
	public static ServerSocketChannel ssc;
	public static SocketChannel socketChannel;
	public static InetAddress server;
	/**
	����һ��ServerSocketChannel����һ��Selector�����Ұ����server channel ע�ᵽ selector�ϣ�ע���ʱ��ָ�������channel ���о���Ȥ���¼��� SelectionKey.OP_ACCEPT������¼���������пͻ��˷���TCP��������
	ʹ�� select ��������ס�̣߳���select ���ص�ʱ���̱߳����ѡ���ͨ��selectedKeys�����õ����п���channel�ļ��ϡ�
	����������ϣ��������channel �������ӵ���ͽ����µ����ӣ�Ȼ�������µ�����Ҳע�ᵽselector��ȥ��
	*******************
	�����channel�Ƕ����ǾͰ����ݶ����������Ұ�������Ȥ���¼��ĳ�д�������д���Ͱ�����д��ȥ�����ҰѸ���Ȥ���¼��ĳɶ���
	*******************
	*A channel that has connected SUCCESSFULLY to another server is "connect ready". 
	*A server socket channel which accepts an incoming connection is "accept" ready.
	*
	*����������н��(����һ����ͨ��,��������client(����PairSocketClient.java)����0x61 ����. ������client�յ�114, ��receive��'r'��ascii):
	*is accessable
     is readable
     received: a
     is writable
     is readable
	*/	
    public static void main(String[] args) {
    	try {
    		server = InetAddress.getByName("172.20.1.2");
			ssc = ServerSocketChannel.open();
			//Ҫ��SocketAddrss��, ��SocketAddrss���ù���,�������и�����InetSocketAddress.
			ssc.bind(new InetSocketAddress(server,50000));
			ssc.configureBlocking(false); //��selector���ʱ, channel ������Ϊ������ģʽ.
			
			//ע��channel, ָ������Ȥ����
			Selector selector = Selector.open();
			//һ��selector,���channel,һ���༶�����ѧ����channleע�ᵽselector�ϣ�ѧ��ע�ᵽ�༶�channel.regisiter(channel)
			//ֻҪע�����,û��Ҫ����key. ��Ϊ�ں���while(true)���и��ַ��ص�key.
			/*SelectionKey key = */
			ssc.register(selector, SelectionKey.OP_ACCEPT);
			
			ByteBuffer readBuffer = ByteBuffer.allocate(1024);
			ByteBuffer writeBuffer = ByteBuffer.allocate(1024);
						
			while(true){
				//�ܹؼ�,��ȻcntReady�������û��,��selector.select()��һ�����Ǳ�Ҫ��, ����ֻѡһ��, ����Ѹ���Ȥ���¸ĳ�read, write��,SelectedKeyҲ���ٸ�����.
				/*int cntReady = */selector.select(); 
				Set <SelectionKey> keys = selector.selectedKeys();
				Iterator<SelectionKey> it = keys.iterator();
				
				while(it.hasNext()){
					SelectionKey key = it.next();
					it.remove();
					
					if(key.isAcceptable()){
						System.out.println("is accessable");
						//����������,��ע�ᵽselector��. ���channelֻ�Զ���������Ȥ.
						socketChannel = ssc.accept();
						socketChannel.configureBlocking(false);
						socketChannel.register(selector ,SelectionKey.OP_READ);
					}else if(key.isReadable()){
						System.out.println("is readable");
						//���key��channel�ж����ܶ�, SelectionKey is a token representing the registration of a SelectableChannel with a Selector.
						socketChannel = (SocketChannel) key.channel();
						readBuffer.clear(); //�����.ע��, ByteBufferֻ������positionָ���limitָ�룬����mark���.���ݲ��ᱻ���,ֻ�ᱻ����.�������϶���������û��
						//����buffer,������array()����ȡbuffer�е�����. ��buffer.position().https://stackoverflow.com/questions/37787987/java-bytebuffer-clear-data
						socketChannel.read(readBuffer);//���ݴ�channel��buffer��Ϊ�Ƕ�����. ����/������selector,һ��selector��һ��buffer�������channel������. 
														//�������߶���channel.
						//serversocketchannel��û��read(), write()��������Ϊserverֻ������accept()֮��᷵��һ��socketchannel���Զ�(client)ͨ��ͬSocket/ServerSocket
						readBuffer.flip();//�Ӷ���дת��.ע���ǴӴ�channel���뵽д��channel��ת��,���԰�position��0,���ܰ�buffer����������ݶ��ܶ���,������ȷд�뵽channel.
						System.out.println("received: "+ new String(readBuffer.array())); //readBuffer.toString();
						key.interestOps(SelectionKey.OP_WRITE);
					}else if(key.isWritable()){
						System.out.println("is writable");
						socketChannel = (SocketChannel) key.channel();
						/*��ByteBuffer��д����,Ȼ����д��channel��. ByteBuffer.put()����channel��д, ByteBuffer.wrap()�ǰ�ĳ��������һ���ֽ������װ�����ŵ�channel��, 
						 * ������������ByteBuffer.��: ByteBuffer send = ByteBufer.warp("hello".getBytes()). ��ʵ���˶���ӳ�ʼ��, Buffer�����������鳤��. 
						 * ����buffer������ݺ������������,һ�Ķ���*/
						writeBuffer.put("received from client".getBytes());
						writeBuffer.flip();
						socketChannel.write(writeBuffer);//buffer -->channel. ������д��ͨ����ȥ.����/������selector,һ��selector��һ��buffer������channel����.
						key.interestOps(SelectionKey.OP_READ);
					}
				}
			}
						
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}