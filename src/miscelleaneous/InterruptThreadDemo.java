package miscelleaneous;

/*
 * �̱߳�����ʱ����ֹ����.���統һ���߳�������Ҫ�Ⱥ��������������������ߵ���Thread.join()����������Thread.sleep()������
 * DataInputStream.read(),�̴߳��ڴ��ڲ�������״̬ʱ����ʹ�������н����̵߳Ĺ����������Ϊtrue�������̴߳�ʱ�����޷����ѭ����־����ȻҲ���޷������жϡ�
 * ��Thread�ṩ��interrupt()��������Ϊ�÷�����Ȼ�����ж�һ���������е��̣߳���������ʹ���������߳��׳�һ���ж��쳣���Ӷ�ʹ�߳���ǰ��������״̬���˳��������롣
 * ����interrupt�����������̲߳�û��ʵ�ʱ��жϣ����������ִ�С�ֻ�Ǹ��𷢳�Ҫ�󣬾���ִ�����������ʵ�֡�
 * ���ȿ�һ�¸÷�����ʵ�֣�
public static boolean interrupted () {
     return currentThread().isInterrupted(true);
}
�÷�������ֱ�ӵ��õ�ǰ�̵߳�isInterrupted(true)������
Ȼ��������һ�� isInterrupted��ʵ�֣�
public boolean isInterrupted () {
     return isInterrupted( false);
}
interrupted �������ڵ�ǰ�̣߳�isInterrupted �������ڵ��ø÷������̶߳�������Ӧ���̡߳����̶߳����Ӧ���̲߳�һ���ǵ�ǰ���е��̡߳�
�������ǿ�����A�߳���ȥ����B�̶߳����isInterrupted��������
����Ĳ���( boolean ClearInterrupted),��״̬λ. �ܺ����֣�ֻ�е�ǰ�̲߳�������Լ����ж�λ����Ӧinterrupted����������
 */
class A extends Thread {
	volatile boolean stop = false;

	public void run() {
		while (!stop) {
			System.out.println(getName() + " is running " + System.currentTimeMillis());
			try {
				sleep(3 * 1000);
			} catch (InterruptedException e) {
				System.out.println("week up from blcok...");
				stop = true; // ���쳣����������޸Ĺ��������״̬
			}
		}
		System.out.println(getName() + " is exiting...");
	}
}

public class InterruptThreadDemo {
	public static void main(String[] args) throws InterruptedException {
		A m1 = new A();
		System.out.println("Starting thread...");
		m1.start(); // ���������run()������,����һֱͣ��while��,��Ϊm1�ǳ������һ���߳�,����һ���� main
					// �����߳�,�������Thread. ��ʱ�����߳�����.
		// ���߳�ʱ,ʵ��Runnableû��start()����,ֻ�м̳�Thread����.���A����ʵ��Runnable,����A
		// m1 = new A()֮���ټ�һ��
		// Thread t1 = new Thread(m1);Ȼ��t1������start(). ���ջ���ͨ��Thread����һ���߳�.

		Thread.sleep(1000);
		// System.out.println(Thread.currentThread().getName()+"
		// "+System.currentTimeMillis());
		System.out.println("Interrupt thread...: " + m1.getName());
		// m1.stop = true; // ���ù������Ϊtrue
		m1.interrupt(); // ����ʱ�˳�����״̬
		System.out.println(m1.isInterrupted()); // ʵ������,����ô˷������̵߳�״̬
		System.out.println(m1.interrupted()); // ��̬����,��'��ǰ'�̵߳�״̬
		// If you use interrupted(), what you're asking is "Have I been
		// interrupted since the last time I asked?"
		Thread.sleep(1000); // ���߳�����3���Ա�۲��߳�m1���ж����
		System.out.println("Stopping application....................");
		System.out.println(m1.isAlive() + " " + m1.isInterrupted() + " " + m1.isDaemon());
	}
}