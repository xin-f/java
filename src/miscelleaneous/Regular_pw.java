package miscelleaneous;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Regular_pw {
	static String pw = "  ` ";
	public static void main(String[] s){
		
		// ����Pattern�����ұ���һ���򵥵�������ʽ"Kelvin"
		Pattern p = Pattern.compile("Kelvin");
		// ��Pattern���matcher()��������һ��Matcher����
		String target = "Kelvin Li and Kelvin Chan are both working in Kelvin Chen's KelvinSoftShop company";
		Matcher m = p.matcher(target);
		StringBuffer sb = new StringBuffer();
		StringBuffer sb2 = new StringBuffer();
		int i = 0;
		// ʹ��find()�������ҵ�һ��ƥ��Ķ���
		boolean result = m.find();
		System.out.println(m.start()+" "+m.end()); //����õ�����0 6, ��end()����1,ָ����� ����. Ҫ��ִ��.find()��������ִ������.
		// ʹ��ѭ�������������е�kelvin�ҳ����滻�ٽ����ݼӵ�sb��
		while (result) {
			i++;
			m.appendReplacement(sb, "Kevin");	//m�Ǹ�ƥ����,����ƥ�乫ʽ(������ʽ)��p. ƥ�������ù�ʽ p ��Ŀ���ַ�������ƥ��. ƥ��ɹ�һ��,�Ͱ����ƥ�䵽���ַ������ɷ���\
			//appendReplacement()�ĵڶ�������,Ȼ�󸳸���һ������. ͬʱԭƥ���� �ַ�����index�ܵ���ƥ�䵽���ַ����ĺ���,�������,��1 ��ƥ���,ԭtarget�ַ�������������6,��ǰ���m.end().
			System.out.println("��" + i + "��ƥ���sb�������ǣ�" + sb);
			
			result = m.find();
		}
		// ������appendTail()���������һ��ƥ����ʣ���ַ����ӵ�sb�
		//It is intended to be invoked after one or more invocations of the appendReplacement() in order to copy the remainder of the input sequence.
		m.appendTail(sb);
		System.out.println("����m.appendTail(sb)��sb������������:" + sb.toString());
		m.appendTail(sb2);
		System.out.println("����m.appendTail(sb2)��sb2������������:" + sb2.toString());
		
		
		/**
		 * basic 
		 */
		Pattern p_alphanumeric  = Pattern.compile("[a-zA-Z0-9_]"); //��Ч��\w
		Pattern p_start = Pattern.compile("^[0-9]"); //�����ֿ�ͷ
		Pattern p_non_word = Pattern.compile("\\W"); //��������,�Ʊ����.
		Pattern p_word = Pattern.compile("\\w");
		Pattern p_visible = Pattern.compile("\\S"); //�κηǿհ��ַ�,���������ո�,��ҳ,�Ʊ����.
		
		Matcher m_alphanumeric = p_alphanumeric .matcher(pw);
		Matcher m_start = p_start.matcher(pw);
		Matcher m_char = p_non_word.matcher(pw);
		Matcher m_word = p_word.matcher(pw);
		Matcher m_visible = p_visible.matcher(pw);
		
		System.out.println(m_alphanumeric.find());
		System.out.println(m_start.find());
		System.out.println(m_char.find());
		System.out.println(m_word.find());
		System.out.println(m_visible.find());
	}

}
