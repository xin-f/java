package security;

import java.util.Formatter;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Random {
	private static String cha = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	private static String upp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static String low = "abcdefghijklmnopqrstuvwxyz";
	private static String dig = "0123456789";
	private static String all = cha + upp + low + dig;
	private static int length;

	public static void main(String[] s) {
		Timer t = new Timer();
		TimerTask timerTask = new TimerTask() {
			public void run() {
				getValidRandomString();
			}
		};
		t.schedule(timerTask, 0, 100);
	}

	private static int getRandom(int i) {
		return (int) Math.round(Math.random() * i);
	}

	/**
	 * �ȴ������ַ����ֻȡһ�����ٴ������ַ���ȡlen-4 �������һ��len����([8,24])���ַ������ٴ���˳��
	 * 
	 * @return
	 */
	public static String getValidRandomString() {
		StringBuffer sb = new StringBuffer();
		length = getRandom(16) + 8;
		sb.append(cha.charAt(getRandom(cha.length() - 1))).append(upp.charAt(getRandom(upp.length() - 1)))
				.append(low.charAt(getRandom(low.length() - 1))).append(dig.charAt(getRandom(dig.length() - 1)));
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
			if (index == 0) {
				if (str.length() == 1) {
					; // �ַ�������Ϊ1ʱ,ʲô������.
				} else {
					str = str.substring(1);
				}
			} else if (index == str.length() - 1) {
				if (str.length() == 2) {
					str = str.substring(0, 1);
				} else
					str = str.substring(0, str.length() - 2); // �ַ�������Ϊ2ʱ,��������.�൱��ʲô��ûȡ��.
			} /*
				 * else if(index == str.length()-2){ str = str.substring(0,
				 * index)+str.substring(str.length()-1); }
				 */else {
				str = str.substring(0, index) + str.substring(index + 1);
			}
			if (str.length() == 0) {
				break;
			}
		}
		Formatter fmt = new Formatter();
		fmt.format("%-26s %d", result, result.length());
		// System.out.printf("%-30s %d",result,result.length());
		System.out.println(fmt);
		if (Frame.ip != null)
			Frame.updateTextArea(fmt.toString() + "\n");
		if (result.length() != sb.length())
			System.exit(0);
		return result.toString();
		// System.out.println();
	}
/**
 * ���һ��1-24λ���ȵ�����ַ���
 * @return
 */
	public static String getRandomString() {
		String cha = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
		String upp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		String low = "abcdefghijklmnopqrstuvwxyz";
		String dig = "0123456789";
		String all = cha + upp + low + dig;
		int length = all.length();

		StringBuffer target = new StringBuffer();
		int random = (int) Math.round(Math.random() * 23); // Ŀ���ַ���,1��24λ.
		for (int i = 0; i <= random; i++) {
			int random_all = (int) Math.round(Math.random() * (length - 1)); // �ַ�����index
			target.append(all.charAt(random_all));
		}
		Formatter fmt = new Formatter();
		fmt.format("%-26s %d", target, target.length());
		// System.out.printf("%-30s %d",result,result.length());
		System.out.println(fmt);
		if (Frame.ip != null)
			Frame.updateTextArea(fmt.toString() + "\n");
		return target.toString();
	}
/**g]V9AzJk
 * �ж�getRandomString()���Ե��ַ����Ƿ���������淶��
 * @param target
 * @return
 */
	public static boolean judge(String target) {
		Pattern p_low = Pattern.compile("[a-z]");
		Pattern p_up = Pattern.compile("[A-Z]");
		Pattern p_dig = Pattern.compile("[\\d]");
//		Pattern p_cha = Pattern.compile("[ !\\\"#$%&'()*+,-./:;<=>?@[\\\\]^_`{|}~]");
		//�ĸ�\����ƥ��\�������ַ���ת��һ�֣���������ʽ��ת��һ�Ρ�\[, \]�ֱ�ƥ�����ҷ����ţ��ٰѷ�б��ת��һ�Σ���\\[,\\]ƥ�����ҷ����š�
		Pattern p_cha = Pattern.compile("[\\\\\" !#$%&'()*+,-./:;<=>?@^_`{|}~\\[\\]]"); 
		Matcher m_low = p_low.matcher(target);
		Matcher m_up = p_up.matcher(target);
		Matcher m_dig = p_dig.matcher(target);
		Matcher m_cha = p_cha.matcher(target);

		if (m_low.find() && m_up.find() && m_cha.find() && m_dig.find() && (target.length() >= 8))
			return true;
		else
			return false;
	}
}
