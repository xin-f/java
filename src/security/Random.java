package security;

import java.util.Formatter;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Random {
    public static String cha = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    public static String upp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static String low = "abcdefghijklmnopqrstuvwxyz";
    public static String dig = "0123456789";
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
     * 先从四类字符里各只取一个，再从所有字符里取len-4 个，组成一个len长度([8,24])的字符串，再打乱顺序。
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
//      String tmp;
        StringBuffer result = new StringBuffer();
        char c;
        int pos;
        for (int i = 0; i < length; i++) {
            pos = getRandom(length -1 - i );
            c = str.charAt(pos);
            result.append(c);
            if(pos == 0)
                str = str.substring(1);
            else if (pos== (length-1))
                str = str.substring(0, length - 1);
            else
                str = str.substring(0, pos) + str.substring(pos + 1);
            }
        Formatter fmt = new Formatter();
        fmt.format("%-26s %d", result, result.length());
        // System.out.printf("%-30s %d",result,result.length());
        System.out.println(fmt);
        if (FrameSecurity.host != null)
            FrameSecurity.updateTextArea(fmt.toString() + "\n");
//      if (result.length() != sb.length())
//          System.exit(0);
        return result.toString();
    }
    
    /**
     * 遍历每个类型，每个字符。
     * 需求：每个类型每个字符出现时，比如大A，该类型其它字符均不出现，其它类型即小写，数字，符号都必须有。 大A是唯一的大写字母。这样可以测试两个方面：
     * 1，大A可被接受，2，大A被当作大写，因为没有其它大写了。对每一类每一个字符都这样处理。
     * @return
     */
    public static String getValidRandomString_traverse() {
        StringBuffer sb = new StringBuffer();
        length = getRandom(16) + 7;
        int len_traverse = 0;
        // 以下四个判断，确保未被勾选的字符类型至少出现一次。比如，勾选大写字母，则小写，数字，符号都会出现，但大写不会出现。大写在SetPassword.java中用charAt()取。
        if(FrameSecurity.charset != FrameSecurity.Charset.cha) {
            sb.append(cha.charAt(getRandom(cha.length() - 1)));
        }
        if(FrameSecurity.charset != FrameSecurity.Charset.upp) {
            sb.append(upp.charAt(getRandom(upp.length() - 1)));
        }
        if(FrameSecurity.charset != FrameSecurity.Charset.dig) {
            sb.append(dig.charAt(getRandom(dig.length() - 1)));
        }
        if(FrameSecurity.charset != FrameSecurity.Charset.low) {
            sb.append(low.charAt(getRandom(low.length() - 1)));
        }

        // for()把字符串由3位扩展到7~23位长度,且依然不包含勾选的字符类。
        for (int i = 0; i < length - 3; i++) {
            if (FrameSecurity.charset == FrameSecurity.Charset.cha) {
                len_traverse = (upp + low + dig).length();
                sb.append((upp + low + dig).charAt(getRandom(len_traverse - 1)));
            }
            if (FrameSecurity.charset == FrameSecurity.Charset.upp) {
                len_traverse = (cha + low + dig).length();
                sb.append((cha + low + dig).charAt(getRandom(len_traverse - 1)));
            }
            if (FrameSecurity.charset == FrameSecurity.Charset.low) {
                len_traverse = (cha + upp + dig).length();
                sb.append((upp + cha + dig).charAt(getRandom(len_traverse - 1)));
            }
            if (FrameSecurity.charset == FrameSecurity.Charset.dig) {
                len_traverse = (cha + low + upp).length();
                sb.append((upp + low + cha).charAt(getRandom(len_traverse - 1)));
            }
        }
        String str = sb.toString();
        StringBuffer result = new StringBuffer();
        char c;
        int pos;
        for (int i = 0; i < length; i++) {
            pos = getRandom(length -1 - i );
            c = str.charAt(pos);
            result.append(c);
            if(pos == 0)
                str = str.substring(1);
            else if (pos== (length-1))
                str = str.substring(0, length - 1);
            else
                str = str.substring(0, pos) + str.substring(pos + 1);
            }
        Formatter fmt = new Formatter();
        fmt.format("%-26s %d", result, result.length() + 1);
        System.out.println(fmt);
        if (FrameSecurity.host != null)
            FrameSecurity.updateTextArea(fmt.toString() + "\n");
        if (result.length() != sb.length())
            System.exit(0);
        return result.toString();
    }

    
/**
 * 获得一个1-30位长度的随机字符串
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
        int random = (int) Math.round(Math.random() * 29); // 目标字符串,1到30位.
        for (int i = 0; i <= random; i++) {
            int random_all = (int) Math.round(Math.random() * (length - 1)); // 字符串的index
            target.append(all.charAt(random_all));
        }
        Formatter fmt = new Formatter();
        fmt.format("%-32s %d", target, target.length());
        // System.out.printf("%-30s %d",result,result.length());
        System.out.println(fmt);
        if (FrameSecurity.host != null)
            FrameSecurity.updateTextArea(fmt.toString() + "\n");
        return target.toString();
    }
/**g]V9AzJk
 * 判断getRandomString()得以的字符串是否满足密码规范。
 * @param target
 * @return
 */
    public static boolean judge(String target) {
        Pattern p_low = Pattern.compile("[a-z]");
        Pattern p_up = Pattern.compile("[A-Z]");
        Pattern p_dig = Pattern.compile("[\\d]");
//      Pattern p_cha = Pattern.compile("[ !\\\"#$%&'()*+,-./:;<=>?@[\\\\]^_`{|}~]");
        //四个\才能匹配\，即到字符串转义一字，到正则表达式再转义一次。\[, \]分别匹配左右方括号，再把反斜杠转义一次，即\\[,\\]匹配左右方括号。
        Pattern p_cha = Pattern.compile("[\\\\\" !#$%&'()*+,-./:;<=>?@^_`{|}~\\[\\]]"); 
        Matcher m_low = p_low.matcher(target);
        Matcher m_up = p_up.matcher(target);
        Matcher m_dig = p_dig.matcher(target);
        Matcher m_cha = p_cha.matcher(target);

        if (m_low.find() && m_up.find() && m_cha.find() && m_dig.find() && (target.length() >= 8) && (target.length() <= 24))
            return true;
        else
            return false;
    }
}
