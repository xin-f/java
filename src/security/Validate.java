package security;

import java.io.UnsupportedEncodingException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Random;

public class Validate {
    /**
     * 程序只用到了解码功能，是跟明文的用户名对比。
     * 编码功能是用来生成授权码的。
     */
    Base64.Decoder decoder = Base64.getDecoder();
    Base64.Encoder encoder = Base64.getEncoder();
    
    //username编码一次再加上原码，再编一次.
    private String encode(String str) {
        String user = str;
        String result = null;
        try {
            result = encoder.encodeToString(user.getBytes("UTF-8"));
            int n = LocalDate.now().getDayOfWeek().getValue();
            result = result + n + result;
            result = encoder.encodeToString(result.getBytes("UTF-8"));
            System.out.println("encode result: "+result);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return result;
    }
    
    //跟encode（）类似，生成授权码。如果以等号（=）结尾，再生成一次。
    public String getAuthoricatedCode(String str) {
        String tmp = str;
        String result = encode(tmp);
        while(result.endsWith("=")) {
            int i = new Random().nextInt(25);
            tmp += "abcdefghijklmnopqrstuvwxyz".charAt(i);
//            System.out.println(i+" "+tmp);
            result = encode(tmp);
        }
        return result;
    }
    /**
     * 注意解码时，如果得到6bit的值为0，那就是A。因为Base64的字典，不是ascii码表，而是A-Za-z0-9+/。Base64码表A排第一。
     * @param src
     * @return
     */
    public String decode(String src) {
        String tmp = src;
        String result = null;
        byte[] output = null;
        try {
            output = decoder.decode(tmp);
        } catch (IllegalArgumentException e) {
            FrameSecurity.updateTextArea("Invalid authorization code\n");
            System.out.println("Authorization code is not in valid Base64 scheme.");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < output.length; i++) {
            sb.append((char) output[i]);
        }
        System.out.println("decode mid result: " + sb);
        int n = (sb.length() - 1) / 2;
        result = sb.substring(0, n);
        output = decoder.decode(result);
        sb = new StringBuilder();
        for (int i = 0; i < output.length; i++) {
            sb.append((char) output[i]);
        }
        System.out.println("decode result: " + sb);
        return sb.toString();
    }
    
    public static void main(String[] args) {
       Validate v =  new Validate();
       v.decode(v.encode("z0034dck"));
       v.decode(v.getAuthoricatedCode("z0034dck"));
    }
}
