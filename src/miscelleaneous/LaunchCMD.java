package miscelleaneous;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;

public class LaunchCMD {
	public static void main(String[] args) {
		/*cmd.exe /c ����ļ�,�൱��˫��,Ȼ����Ĭ�Ϲ����ĳ����; �������,�൱��˫���򿪳���,
		 * ��,����ֻ�ܸ�һ������,�����������ո��·��ʱ,Ҫ��·����˫���Ű�����.
		 * �ñ�����ʾʱ: ("\""+t_path+"\"")
		 * 
		 * cmd ����/c��������������/c���������, ����ֻ����cmd. ����������������CMD /C DIR C:��CMD DIR C:
		 * cmd /c dir ��ִ����dir�����ر�����ڡ�
		 * cmd /k dir ��ִ����dir����󲻹ر�����ڡ�
		 * cmd /c start dir ���һ���´��ں�ִ��dirָ�ԭ���ڻ�رա�
		 * cmd /k start dir ���һ���´��ں�ִ��dirָ�ԭ���ڲ���رա�
		 */
		String file = "cmd.exe /c  \"D:\\Program Files\\readme.txt\"";//ֻ�ܴ�һ������,���Զ����һ������,�����־���ת��.
		String program = "cmd.exe /c \"D:\\Program Files\\FirmwareUpdate.exe\"";
		String program1 = "D:\\Program Files\\FirmwareUpdate.exe";
		String file_prog = "D:\\tools\\Notepad++.7.3.bin.x64\\notepad++.exe D:\\Program Files\\readme.txt";//�����Ҫ�򿪵��ļ�.
		String ping = "ping 172.20.1.24 -t";
		String str;
		try {
//			Process p = Runtime.getRuntime().exec(file);
//			Process p1 = Runtime.getRuntime().exec(program);
//			Process p11 = Runtime.getRuntime().exec(program);
//			Process p2 = Runtime.getRuntime().exec(file_prog);
			Process p3 = Runtime.getRuntime().exec(ping);
			BufferedReader in = new BufferedReader(new InputStreamReader(p3.getInputStream()));
			while((str = in.readLine())!=null) 
				System.out.println(str);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }

}
