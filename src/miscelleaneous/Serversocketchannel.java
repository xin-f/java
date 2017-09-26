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
	创建一个ServerSocketChannel，和一个Selector，并且把这个server channel 注册到 selector上，注册的时间指定，这个channel 所感觉兴趣的事件是 SelectionKey.OP_ACCEPT，这个事件代表的是有客户端发起TCP连接请求。
	使用 select 方法阻塞住线程，当select 返回的时候，线程被唤醒。再通过selectedKeys方法得到所有可用channel的集合。
	遍历这个集合，如果其中channel 上有连接到达，就接受新的连接，然后把这个新的连接也注册到selector中去。
	*******************
	如果有channel是读，那就把数据读出来，并且把它感兴趣的事件改成写。如果是写，就把数据写出去，并且把感兴趣的事件改成读。
	*******************
	*A channel that has connected SUCCESSFULLY to another server is "connect ready". 
	*A server socket channel which accepts an incoming connection is "accept" ready.
	*
	*这个程序运行结果(另由一个普通的,即阻塞的client(比如PairSocketClient.java)发了0x61 过来. 最后这个client收到114, 即receive中'r'的ascii):
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
			//要绑到SocketAddrss上, 但SocketAddrss不好构造,不过它有个子类InetSocketAddress.
			ssc.bind(new InetSocketAddress(server,50000));
			ssc.configureBlocking(false); //跟selector配合时, channel 必须设为非阻塞模式.
			
			//注册channel, 指定感兴趣的事
			Selector selector = Selector.open();
			//一个selector,多个channel,一个班级，多个学生，channle注册到selector上，学生注册到班级里。channel.regisiter(channel)
			//只要注册就行,没必要返回key. 因为在后面while(true)里有各种返回的key.
			/*SelectionKey key = */
			ssc.register(selector, SelectionKey.OP_ACCEPT);
			
			ByteBuffer readBuffer = ByteBuffer.allocate(1024);
			ByteBuffer writeBuffer = ByteBuffer.allocate(1024);
						
			while(true){
				//很关键,虽然cntReady这个变量没用,但selector.select()这一操作是必要的, 否则只选一次, 下面把感兴趣的事改成read, write后,SelectedKey也不再更新了.
				/*int cntReady = */selector.select(); 
				Set <SelectionKey> keys = selector.selectedKeys();
				Iterator<SelectionKey> it = keys.iterator();
				
				while(it.hasNext()){
					SelectionKey key = it.next();
					it.remove();
					
					if(key.isAcceptable()){
						System.out.println("is accessable");
						//创建新连接,并注册到selector上. 这个channel只对读操作感兴趣.
						socketChannel = ssc.accept();
						socketChannel.configureBlocking(false);
						socketChannel.register(selector ,SelectionKey.OP_READ);
					}else if(key.isReadable()){
						System.out.println("is readable");
						//这个key的channel有东西能读, SelectionKey is a token representing the registration of a SelectableChannel with a Selector.
						socketChannel = (SocketChannel) key.channel();
						readBuffer.clear(); //先清掉.注意, ByteBuffer只是重置position指针和limit指针，废弃mark标记.数据不会被清空,只会被覆盖.所以若上读到的数据没有
						//填满buffer,则不能用array()方法取buffer中的数据. 用buffer.position().https://stackoverflow.com/questions/37787987/java-bytebuffer-clear-data
						socketChannel.read(readBuffer);//数据从channel到buffer认为是读过来. 主角/主语是selector,一个selector有一个buffer存放所有channel的数据. 
														//但调用者都是channel.
						//serversocketchannel类没有read(), write()方法，因为server只监听，accept()之后会返回一个socketchannel跟对端(client)通。同Socket/ServerSocket
						readBuffer.flip();//从读到写转换.注意是从从channel读入到写到channel的转换,所以把position置0,即能把buffer里的所有数据都能读到,才能正确写入到channel.
						System.out.println("received: "+ new String(readBuffer.array())); //readBuffer.toString();
						key.interestOps(SelectionKey.OP_WRITE);
					}else if(key.isWritable()){
						System.out.println("is writable");
						socketChannel = (SocketChannel) key.channel();
						/*往ByteBuffer里写数据,然后再写到channel里. ByteBuffer.put()是往channel里写, ByteBuffer.wrap()是把某处得来的一个字节数组包装起来放到channel里, 
						 * 可以用来创建ByteBuffer.如: ByteBuffer send = ByteBufer.warp("hello".getBytes()). 即实现了定义加初始化, Buffer的容量是数组长度. 
						 * 而且buffer里的数据和数组里的联动,一改都改*/
						writeBuffer.put("received from client".getBytes());
						writeBuffer.flip();
						socketChannel.write(writeBuffer);//buffer -->channel. 把数据写到通道里去.主角/主语是selector,一个selector有一个buffer给所有channel共享.
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