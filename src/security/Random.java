package security;

import java.util.Formatter;
import java.util.Timer;
import java.util.TimerTask;

public class Random {
	private static String cha = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	private static String upp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static String low = "abcdefghijklmnopqrstuvwxyz";
	private static String dig = "0123456789";
	private static String all = cha + upp + low + dig;
	private static int length;
	
	public static void main(String[] s) {
		Timer t = new Timer();
		TimerTask timerTask = new TimerTask(){
			public void run() {
				getRandomString();
			}			
		};
		t.schedule(timerTask, 0, 100);		
	}
	private static int getRandom(int i) {
		return (int) Math.round(Math.random() * i);
	}
/**
 * 先从四类字符里各只取一个，再从所有字符里取len-4 个，组成一个len长度([8,24])的字符串，再打乱顺序。
 * @return
 */
	public static String getRandomString() {
		StringBuffer sb = new StringBuffer();
		length = getRandom(16) + 8; 
		sb.append(cha.charAt(getRandom(cha.length()-1)))
			.append(upp.charAt(getRandom(upp.length()-1)))
			.append(low.charAt(getRandom(low.length()-1)))
			.append(dig.charAt(getRandom(dig.length()-1)));
		int len_all = all.length();
		for (int i = 0; i < length - 4; i++) {
			sb.append(all.charAt(getRandom(len_all - 1)));
		}
		String str = sb.toString();
		String tmp;
		StringBuffer result = new StringBuffer();
		char c;
		for (int i = 0; i < length; i++) {
			c = str.charAt(getRandom(str.length() - 1));
			result.append(c);
			int index = str.indexOf(c);
			if(index == 0){
				if(str.length() == 1){	;		//字符串长度为1时,什么都不做.		
				}else{
					str = str.substring(1);
				}				
			}else if(index == str.length()-1){
				if(str.length() == 2){
					str = str.substring(0, 1);
				}else
				str = str.substring(0, str.length()-2); //字符串长度为2时,这里会出错.相当于什么都没取到.
			}/*else if(index == str.length()-2){
				str = str.substring(0, index)+str.substring(str.length()-1);
			}*/else{
				str = str.substring(0, index)+str.substring(index+1);
			}
			if (str.length() == 0) {
				break;
			}
		}
		Formatter fmt = new Formatter();
		fmt.format("%-30s %d",result,result.length());
//		System.out.printf("%-30s %d",result,result.length());
//		System.out.printf("\n");
		System.out.println(fmt);
		if(Frame.ip != null)
//			Frame.updateTextArea(result+" "+result.length()+"\n");
			Frame.updateTextArea(fmt.toString()+"\n");
		if(result.length() != sb.length()) System.exit(0);
		return result.toString();
//		System.out.println();
	}
}
