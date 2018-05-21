package security;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.text.DefaultCaret;
import javax.swing.JFileChooser;

public class FrameSecurity {

    private static JFrame SecurityTest;
    private static JTextArea textArea;
    private static JTextArea textArea_cnt;
    private static JLabel PERIOD;
    private static JTextField textField_period;
    private static JTextField textField_MntPw;
    private static JTextField textField_fw;
    private static JCheckBox chkbxsave;
    private static JCheckBox chkbxTls;
    private static JCheckBox chkbxAlt;
    private static JCheckBox chkbxSaveCfg;
    private static File file = null;
    private static PrintStream logStream = null;
    private static JTextField textField_DigPW;
    private static JTextField textField_end;
    private static JRadioButton rdbtnD, rdbtnF;
    private static JTextArea textArea_ubound;
    private static Timer t_ping = null; // 新建一线程检查server是否在线。默认启动，Reset复归，每个操作都会再启动。
    private static boolean t_ping_running = false;
    private static Thread thread_neg = null;
    private static JTextArea textArea_prfSave;
    private static JTextArea textArea_prfUp;
    public static JTextField textField_ip;
    public static String host;
    public static String ip_another;
    public static int period;
    public static int certEnd;
    public static int fwEnd; // 给一个IP段下firmware时最后一个，从界面读入的。
    public static int sprfEnd; // 给一个IP段下sprf时最后一个，从界面读入的。
    public static String mntpw;
    public static String digpw;
    public static String commonpw;// fwpw 和digpw
                                  // 由同一个函数管理，这个公共密码用来在fwpw和digpw都没设时，点不同按钮，能把界面上相应两个字符串送到不同密码。用在SetPassword里
    public static String fw;
    public static boolean fwpwRunning; // password is being set. 用于点Reset后停止改密码的loop, 以及与其它操作的互斥。
    public static boolean digpwRunning; // password is being set. 用于点Reset后停止改密码的loop, 以及与其它操作的互斥。
    public static boolean fwRunning; // fw is being uploaded. 用于点Reset后停止改密码的loop, 以及与其它操作的互斥。
    public static boolean chkRunning; // 检查证书. 用于与其它操作的互斥。
    public static boolean negRunning; // 反向测试运行中，即1-24位随机字符串设密码。也不一定都是反向测试，存在字符串满足密码条件的情况。
    public static boolean debug;
    public static boolean ForFun; // get the certificate such as baidu.com
    public static boolean negative;
    private static int ctlVal;
    public static boolean certSegment; // 检查一个IP段的证书.
    public static boolean fwSegment; // 下一个IP段的firmware.
    public static boolean sprfSegment; // 读一个IP段的sprf.
    public static int ubound; // 循环次数达到此值即停。
    public static boolean ChangePw;// 为真时，用另一个密码框的字符串作为目标密码修改当前密码。即互为目标密码。
    public static JCheckBox chkbxA;
    public static JCheckBox chkbxa;
    public static JCheckBox chkbx0;
    public static JCheckBox chkbx_;
    public static boolean serverLost = false;
    public static boolean stopped;
    // public static boolean reset;
    // //表示R按钮被点过至少一次。用到手动设了密码，停下，或清掉，再手动设一次。不加这个量，再点R按钮时会继续用新字符串来改/设密码。
    public static boolean save;
    public static boolean tls;
    public static FrameSecurity window;
    public static boolean alter;
    public static boolean traverse;
    public static boolean traverseA;
    public static boolean traversea;
    public static boolean traverse0;
    public static boolean traverse_;
    public static boolean turn;
    public static boolean attack;
    // public static boolean saveCfg;
    public static JRadioButton rdbtnTCPOff, rdbtnTCPOn;
    public static JRadioButton rdbtnDTLSOff, rdbtnDTLSOn;
    public static String prfDirectory = "";
    public static String prfFile = "";
    public static String prfFileFromSelect = "";

    public enum Optype {
        digsi, fw
    }

    public enum Charset {
        upp, low, dig, cha
    }

    public static Charset charset;
    private static JButton btnFile;
    // private static JTextArea textArea_prf_save;
    // private static JTextArea textArea_prfUp;
    private static JButton btnResetPW;

    private static String user;
    private static String userInput;
    public static String input;
    public static boolean UserAuth;// 下面两个的或运算结果
    public static boolean UserAuthOneTime;// 一次性
    public static boolean UserAuthPermanant; // 用于序列化
    public static Validate v;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    window = new FrameSecurity();
                    readCfg();
                    UserAuth = UserAuthPermanant;
                    if (!UserAuth) {
                        v = new Validate();
                        user = System.getProperty("user.name");
                    }
                    buildTextArea();
                    SecurityTest.setVisible(true);

                    /*
                     * String str = textField_MntPw.getText(); tls = chkbxTls.isSelected(); if (tls)
                     * ip = "https://" + textField_ip.getText() + "/setupsecureengineeringaccess";
                     * else ip = "http://" + textField_ip.getText() +
                     * "/setupsecureengineeringaccess";
                     * Common.checkCurrent("/setupsecureengineeringaccess");
                     * Common.checkCurrent("/setupwebmonitoraccess");
                     */

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Create the application.
     */
    public FrameSecurity() {
        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize() {
        SecurityTest = new JFrame();
        SecurityTest.setTitle("Security Test  -V01.01 by SXF");
        SecurityTest.setBounds(100, 100, 399, 450);
        SecurityTest.setLocationRelativeTo(null);
        SecurityTest.setResizable(false);
        SecurityTest.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        SecurityTest.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent e) {
                exit();
            }
        });
        SecurityTest.getContentPane().setLayout(null);

        JLabel IPADDR = new JLabel("IP");
        IPADDR.setBounds(10, 11, 17, 22);
        SecurityTest.getContentPane().add(IPADDR);

        textField_ip = new JTextField();
        textField_ip.setBounds(26, 12, 86, 20);
        textField_ip.setText("172.20.1.80");
        SecurityTest.getContentPane().add(textField_ip);
        textField_ip.setColumns(10);

        PERIOD = new JLabel("Prid(0.1s)");
        PERIOD.setBounds(206, 14, 55, 14);
        SecurityTest.getContentPane().add(PERIOD);

        textField_period = new JTextField();
        textField_period.setToolTipText(
                "Ends with \".\" will enable password attack, e.g., \"10.\" means making an attempt every 1 sec");
        textField_period.setBounds(263, 11, 33, 20);
        textField_period.setText("3000");
        SecurityTest.getContentPane().add(textField_period);
        textField_period.setColumns(10);

        JButton btnFwPW = new JButton("MntPW"); // Set Firmware upload password
        btnFwPW.setToolTipText("Set maintenance password cyclically with specified PERIOD.");
        btnFwPW.setBounds(210, 34, 86, 23);
        btnFwPW.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                /*
                 * if(!t_ping_running) { t_ping = new Timer(); t_ping.schedule(new Ping(), 0,
                 * 5000); t_ping_running = true; }
                 */
                if (UserAuth) {
                    updateTextArea("Setting maintenance password:\n");
                    enablePing();
                    alter = chkbxAlt.isSelected();
                    alter = chkbxAlt.isSelected();
                    if (alter) {
                        ip_another = getIP(textField_ip.getText(), Optype.digsi);
                    }
                    stopped = false;
                    attack = false;
                    ubound = 0;
                    if ((!fwRunning) && (!digpwRunning) && (!fwpwRunning)) {
                        debug = false;
                        fwpwRunning = true;
                        ubound = 0;
                        prepare_setFwPW();
                        checkUbound();
                        prepare_traverse();
                        if (debug) {
                            file = new File("log.txt");
                            try {
                                logStream = new PrintStream(new FileOutputStream(file));
                            } catch (FileNotFoundException e1) {
                                e1.printStackTrace();
                            }
                            System.setOut(logStream);
                            System.setErr(logStream);
                        }
                        if (attack) {
                            SetPassword.set();
                        } else {
                            if ((period != 0) && (period < 50)) {
                                updateTextArea("To avoid timeout, set the period no less than 5s.\n");
                            } else {
                                if (period == 0) {
                                    updateTextArea(
                                            "You want to change pw to specified one. Make sure the passwrods in two fields are different.\n");
                                }
                                SetPassword.set();
                            }
                        }
                    } else if (fwRunning) {
                        updateTextArea("FW uploading is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (digpwRunning) {
                        updateTextArea("Digsi connection pw Setting is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (fwpwRunning) {
                        updateTextArea("The operation is already in progress!! \n");
                    }
                } else {
                    updateTextArea("Input authorization code to enable the button.\n");
                }
            }
        });
        SecurityTest.getContentPane().add(btnFwPW);

        JLabel lblDigpw = new JLabel("DigPW");
        lblDigpw.setBounds(10, 60, 40, 22);
        SecurityTest.getContentPane().add(lblDigpw);

        textField_DigPW = new JTextField();
        // textField_DigPw.setText("21!qQ/nm`hMi),52(x@= /nm`hMi),52(x@= /nm`hMi),52(x@=
        // /nm`hMi),52(x@=");
        textField_DigPW.setText("1!qQ1111");
        textField_DigPW.setColumns(10);
        textField_DigPW.setBounds(54, 60, 155, 20);
        SecurityTest.getContentPane().add(textField_DigPW);

        JButton btnDigPW = new JButton("DigPW");
        btnDigPW.setToolTipText("Set Digsi connection password cyclically with specified PERIOD.");
        btnDigPW.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                /*
                 * if(!t_ping_running) { t_ping = new Timer(); t_ping.schedule(new Ping(), 0,
                 * 5000); t_ping_running = true; }
                 */
                if (UserAuth) {
                    updateTextArea("Setting DIGSI connection password:\n");
                    enablePing();
                    alter = chkbxAlt.isSelected();
                    if (alter) {
                        ip_another = getIP(textField_ip.getText(), Optype.fw);
                    }
                    stopped = false;
                    attack = false;
                    ubound = 0;
                    if ((!fwRunning) && (!fwpwRunning) && (!digpwRunning)) {
                        debug = false;
                        digpwRunning = true;
                        ubound = 0;
                        prepare_setDigPW();
                        checkUbound();
                        // if(prepare_traverse()>1) {
                        // return; //遍历的字符类型大于一个，退出当前方法，重新选。
                        // }
                        prepare_traverse();
                        if (debug) {
                            file = new File("log.txt");
                            try {
                                logStream = new PrintStream(new FileOutputStream(file));
                            } catch (FileNotFoundException e1) {
                                e1.printStackTrace();
                            }
                            System.setOut(logStream);
                            System.setErr(logStream);
                        }
                        if (attack) {
                            SetPassword.set();
                        } else {
                            if ((period != 0) && (period < 50)) {
                                updateTextArea("To avoid timeout, set the period no less than 5s.\n");
                            } else
                                SetPassword.set();
                        }
                    } else if (fwRunning) {
                        updateTextArea("FW uploading is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (fwpwRunning) {
                        updateTextArea("Maintenance password setting is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (digpwRunning) {
                        updateTextArea("The operation is already in progress!! \n");
                    }
                } else {
                    updateTextArea("Input authorization code to enable the button.\n");
                }
            }
        });
        btnDigPW.setBounds(210, 60, 86, 23);
        SecurityTest.getContentPane().add(btnDigPW);

        JButton btnReset = new JButton("R");
        btnReset.setToolTipText("Reset");
        btnReset.setBounds(210, 182, 42, 23);
        btnReset.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (!UserAuth) {
                    // if(user.toLowerCase().equals("z0034dck")) UserAuth = true;
                    if (textField_period.getText().equals("-1.5") && textField_end.getText().equals("82")) {
                        updateTextArea(new Validate().getAuthoricatedCode(textField_ip.getText()));
                    } else {
                        input = textField_ip.getText();
                        if (input.equals("security")) {
                            UserAuthOneTime = true;
                            updateTextArea("Validated for one-time use.\n");
                        } else {
                            userInput = input; // 第一次，记下来，用于序列化。
                            if (v.decode(input).toLowerCase().indexOf(user.toLowerCase()) > -1) {
                                updateTextArea("Validation succeeds for user: " + user.toLowerCase() + "\n");
                                UserAuthPermanant = true;
                            } else {
                                updateTextArea("Validation fails for user: " + user.toLowerCase() + "\n");
                            }
                        }
                        UserAuth = UserAuthOneTime || UserAuthPermanant;
                    }
                }
                reset();
            }
        });
        SecurityTest.getContentPane().add(btnReset);

        JButton btnClear = new JButton("C");
        btnClear.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                textArea.setText("");
                updateTextAreacnt(0);
            }
        });
        btnClear.setToolTipText("Clear");
        btnClear.setBounds(254, 182, 42, 23);
        SecurityTest.getContentPane().add(btnClear);

        JLabel lblNumberOfTimes = new JLabel("Cnt of succ oper:");
        lblNumberOfTimes.setBounds(10, 184, 100, 22);
        SecurityTest.getContentPane().add(lblNumberOfTimes);

        JLabel lblFwPw = new JLabel("MntPW");
        lblFwPw.setBounds(10, 34, 42, 22);
        SecurityTest.getContentPane().add(lblFwPw);

        textField_MntPw = new JTextField();
        textField_MntPw.setBounds(54, 35, 155, 20);
        // textField_FwPw.setText("ddfasdfsASDDFSDf4654+65.;''.ddfasdfsASDDFSDf4654+65.;''.'';,!*(#^#^#,
        // ");
        textField_MntPw.setText("1!qQ1111");
        textField_MntPw.setColumns(10);
        SecurityTest.getContentPane().add(textField_MntPw);

        JLabel lblFw = new JLabel("FW");
        lblFw.setBounds(10, 89, 40, 22);
        SecurityTest.getContentPane().add(lblFw);

        textField_fw = new JTextField();
        textField_fw.setBounds(54, 90, 155, 20);
        textField_fw.setText("D:\\IEC61850_81.pck");
        textField_fw.setColumns(10);
        SecurityTest.getContentPane().add(textField_fw);

        JButton btnUpldfw = new JButton("UpldFW");
        btnUpldfw.setToolTipText("Upload FW.");
        btnUpldfw.setBounds(210, 87, 86, 23);
        btnUpldfw.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                /*
                 * if(!t_ping_running) { t_ping = new Timer(); t_ping.schedule(new Ping(), 0,
                 * 5000); t_ping_running = true; }
                 */
                if (UserAuth) {
                    if ((!fwpwRunning) && (!digpwRunning) && (!fwRunning)) {
                        debug = false;
                        fwRunning = true;
                        ubound = 0;
                        prepare_upldFW();
                        if (!fwSegment)
                            enablePing();
                        else {
                            String[] str = textField_ip.getText().split("[.]");
                            t_ping = new Timer(); // 这里注意，只起一个timer，用同一个timer控制所有的ping timertask，要取消时，只要t_ping.cancel()
                            for (int i = Integer.parseInt(str[3]); i <= fwEnd; i++) {
                                enablePingForSeg(i);
                            }
                        }
                        checkUbound();
                        if (debug) {
                            file = new File("log.txt");
                            try {
                                logStream = new PrintStream(new FileOutputStream(file));
                            } catch (FileNotFoundException e1) {
                                e1.printStackTrace();
                            }
                            System.setOut(logStream);
                            System.setErr(logStream);
                        }
                        if (period < 10) {
                            updateTextArea("To avoid timeout, set the period no less than 1s.\n");
                        } else {
                            updateTextArea("Start to transmit firmware file to device...\n");
                            HttpPost.upldFW();
                        }
                    } else if (fwpwRunning) {
                        updateTextArea("FW upload pw setting is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (digpwRunning) {
                        updateTextArea("Digsi connection pw setting is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (fwRunning) {
                        updateTextArea("FW uploading is already in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    }
                } else {
                    updateTextArea("Input authorization code to enable the button.\n");
                }
            }
        });
        SecurityTest.getContentPane().add(btnUpldfw);

        JButton btnCert = new JButton("GtCrt");
        btnCert.setToolTipText("Get server certificate.");
        btnCert.setBounds(300, 81, 75, 23);
        btnCert.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                /*
                 * if(!t_ping_running) { t_ping = new Timer(); t_ping.schedule(new Ping(), 0,
                 * 5000); t_ping_running = true; }
                 */
                if (UserAuth) {
                    enablePing();
                    if ((!fwpwRunning) && (!digpwRunning) && (!fwRunning)) {
                        chkRunning = true;
                        updateTextArea("Checking certificate:\n");
                        updateTextArea("The value in \"Cnt of succ oper:\" should be zero.\n");
                        debug = false;
                        prepare_ChkCert();
                        if (debug) {
                            file = new File("log.txt");
                            try {
                                logStream = new PrintStream(new FileOutputStream(file));
                            } catch (FileNotFoundException e1) {
                                e1.printStackTrace();
                            }
                            System.setOut(logStream);
                            System.setErr(logStream);
                        }
                        if (tls)
                            GetCertificate.checkCert();
                    } else if (fwpwRunning) {
                        updateTextArea("FW upload pw setting is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (digpwRunning) {
                        updateTextArea("Digsi connection pw setting is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    } else if (fwRunning) {
                        updateTextArea("FW uploading is in progress!! \n" + "Click 'Reset', wait "
                                + textField_period.getText() + " seconds and try again.\n");
                    }
                } else {
                    updateTextArea("Input authorization code to enable the button.\n");
                }
            }
        });
        SecurityTest.getContentPane().add(btnCert);

        JButton btnNegPw = new JButton("Negtiv");
        btnNegPw.setToolTipText("Negative test.");
        btnNegPw.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                enablePing();
                stopped = false;
                negative = true;
                negRunning = true;
                ubound = 0;
                prepare_setNegPW();
                // prepare_traverse();
                checkUbound();
                Thread_neg a = new Thread_neg();
                thread_neg = new Thread(a);
                thread_neg.start();

            }
        });
        btnNegPw.setBounds(300, 34, 75, 23);
        SecurityTest.getContentPane().add(btnNegPw);

        rdbtnD = new JRadioButton("D");
        rdbtnD.setToolTipText("set digsi connection pw");
        rdbtnD.setBounds(302, 55, 33, 23);
        SecurityTest.getContentPane().add(rdbtnD);

        rdbtnF = new JRadioButton("M");
        rdbtnF.setToolTipText("set maintenance pw");
        rdbtnF.setSelected(true);
        rdbtnF.setBounds(337, 55, 35, 23);
        SecurityTest.getContentPane().add(rdbtnF);

        ButtonGroup bg_neg = new ButtonGroup();
        bg_neg.add(rdbtnD);
        bg_neg.add(rdbtnF);

        JButton btnTcp = new JButton("TCP");
        btnTcp.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ctlVal = 2;// 非0非1，用于在刚打开两个单选钮都没选中时把值初始化。放在这里不放在外面是因为两个button共用一个ctlVal，即使被干扰了也能回到初始值。
                debug = false;
                prepare_TCP_DTLS(rdbtnTCPOn, rdbtnTCPOff, "/setupwebmonitoraccess");
                if ((ctlVal != 0) && (ctlVal != 1)) {
                    updateTextArea("Select one radio button below.\n");
                } else {
                    enablePing();
                    if (ctlVal == 1) {
                        updateTextArea("Switching on TCP protocol(Enable WebMon).\n");
                    }
                    if (ctlVal == 0) {
                        updateTextArea("Switching off TCP protocol(Disable WebMon).\n");
                    }
                    new ManipulateTCPDTLS("TCP", "/setupwebmonitoraccess", ctlVal,
                            Integer.parseInt(textField_ip.getText().split("[.]")[3])).act();
                }
            }
        });
        btnTcp.setToolTipText("Enable/disable TCP.");
        btnTcp.setBounds(300, 115, 75, 23);
        SecurityTest.getContentPane().add(btnTcp);

        rdbtnTCPOff = new JRadioButton("N");
        rdbtnTCPOff.setToolTipText("Disable TCP");
        rdbtnTCPOff.setBounds(302, 135, 33, 23);
        SecurityTest.getContentPane().add(rdbtnTCPOff);

        rdbtnTCPOn = new JRadioButton("Y");
        rdbtnTCPOn.setToolTipText("Enable TCP");
        // rdbtnTcpOn.setSelected(true);
        rdbtnTCPOn.setBounds(337, 135, 35, 23);
        SecurityTest.getContentPane().add(rdbtnTCPOn);

        ButtonGroup bg_TCP = new ButtonGroup();
        bg_TCP.add(rdbtnTCPOn);
        bg_TCP.add(rdbtnTCPOff);

        JButton btnDtls = new JButton("DTLS");
        btnDtls.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                debug = false;
                ctlVal = 2;// 非0非1，用于在刚打开两个单选钮都没选中时把值初始化。放在这里不放在外面是因为两个button共用一个ctlVal，即使被干扰了也能回到初始值。
                prepare_TCP_DTLS(rdbtnDTLSOn, rdbtnDTLSOff, "/setupsecureengineeringaccess");
                if ((ctlVal != 0) && (ctlVal != 1)) {
                    updateTextArea("Select one radio button below.\n");
                } else {
                    enablePing();
                    if (ctlVal == 1) {
                        updateTextArea("Switching on DTLS protocol.\n");
                    }
                    if (ctlVal == 0) {
                        updateTextArea("Switching off DTLS protocol.\n");
                    }
                    new ManipulateTCPDTLS("DTLS", "/setupsecureengineeringaccess", ctlVal,
                            Integer.parseInt(textField_ip.getText().split("[.]")[3])).act();
                }
            }
        });
        btnDtls.setToolTipText("Enable/disable DTLS.");
        btnDtls.setBounds(300, 162, 75, 23);
        SecurityTest.getContentPane().add(btnDtls);

        rdbtnDTLSOff = new JRadioButton("N");
        rdbtnDTLSOff.setToolTipText("Disable DTLS");
        rdbtnDTLSOff.setBounds(302, 183, 33, 23);
        SecurityTest.getContentPane().add(rdbtnDTLSOff);

        rdbtnDTLSOn = new JRadioButton("Y");
        rdbtnDTLSOn.setToolTipText("Enable DTLS");
        // rdbtnDTLSOn.setSelected(true);
        rdbtnDTLSOn.setBounds(337, 183, 35, 23);
        SecurityTest.getContentPane().add(rdbtnDTLSOn);

        ButtonGroup bg_DTLS = new ButtonGroup();
        bg_DTLS.add(rdbtnDTLSOn);
        bg_DTLS.add(rdbtnDTLSOff);

        JButton btnExit = new JButton("Exit");
        btnExit.setBounds(300, 11, 75, 23);
        btnExit.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                exit();
            }
        });
        SecurityTest.getContentPane().add(btnExit);

        JButton btnMemo = new JButton("Read");
        btnMemo.setToolTipText("Short description.");
        btnMemo.setVisible(false);
        btnMemo.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                updateTextArea("History: \n" + "V1.01: Update according to EN100 function modification.\n"
                        + "V1.01: Initial version.\n" + "'DigPW': Initialize DIGSI connection password with "
                        + "the specified string, then change the password "
                        + "cyclically with period value in 'Prid(0.1s)'. "
                        + "If the password is set already, input current "
                        + "password in the text field then the program will "
                        + "change the password cyclically. It will stop if "
                        + "initializing or changing password fails. "
                        + "If Period is 0, the program will change the password " + "to the string in MntPW. "
                        + "If the value in the second text box(82, in this "
                        + "demo) after 'IP' ends with \".\" (for example, \"82.\"), "
                        + "password attacking will be initiated with 'Prid(0.1s)'.\n"
                        + "'MntPW': The same as 'DigPW', but effect on "
                        + "maintenance password(change password to string in DigPW).\n"
                        + "'UpldFW': If the value in the second text box after 'IP' "
                        + "starts with \".\"(\".82\"), the specified firmware will "
                        + "be uploaded to a cluster of servers(here, from 172.20."
                        + "1.80 to 172.20.1.82, 3 servers in all). Else, the "
                        + "specified firmware will be uploaded to the device "
                        + "specified in the 1st text box(here, 172.20.1.80) repeatedly.\n"
                        + "'Negtiv': together with radio button 'D'(digsi connection pw) "
                        + "or 'M'(maintenance pw), to do negative test: Set any string "
                        + "whose length is 1~30 as password cyclically. If valie "
                        + "password is rejected or invalid password is accepted "
                        + "by EN100, the cyclic work will stop.\n"
                        + "'CkCrt': check certificate. 'tls' must be checked. "
                        + "Just like UpldFW, if the value in the second text box "
                        + "after 'IP' starts with \".\", a cluster of certificates "
                        + "will be get. Else, only the certificate of device specified "
                        + "in the 1st text box will be get.\n"
                        + "'R': reset, to interrupt the cyclic work, and save the "
                        + "log if the checkbox 'save' is checked meanwhile one of "
                        + "DigPW, MntPW, Negtiv, or CkCrt is in progress.\n" + "'C': clear the display.\n"
                        + "'save': Save the passwords that used, or the certificate(s) got from device.\n"
                        + "'a', 'A', '0', '!': traverse all characters. "
                        + "For example, is 'a' is checked, all lowercase characters "
                        + "will be set as password one by one.\n"
                        + "'GetPRF': Download sprf file to specified folder. Only via TCP now :(\n"
                        + "'RsPW': Upload the specified sprf file to reset passwords. "
                        + "If no file is specified, Digsi connection password will be " + "reset(if exists).\n");
            }
        });
        btnMemo.setBounds(310, 378, 65, 23);
        SecurityTest.getContentPane().add(btnMemo);

        textField_end = new JTextField();
        textField_end.setToolTipText("End of IP segment. Starting with \".\" with enable IP segment scan. ");
        textField_end.setText("82");
        textField_end.setColumns(10);
        textField_end.setBounds(115, 12, 30, 20);
        SecurityTest.getContentPane().add(textField_end);

        chkbxsave = new JCheckBox("save");
        chkbxsave.setToolTipText("Save the log");
        chkbxsave.setBounds(310, 268, 60, 23);
        SecurityTest.getContentPane().add(chkbxsave);

        chkbxTls = new JCheckBox("tls");
        chkbxTls.setSelected(true);
        // chkbxTls.setSelected(true);
        chkbxTls.setToolTipText("Enable https function");
        chkbxTls.setBounds(310, 294, 50, 23);
        SecurityTest.getContentPane().add(chkbxTls);

        chkbxAlt = new JCheckBox("alter");
        chkbxAlt.setToolTipText("Set password alternately");
        chkbxAlt.setBounds(310, 320, 60, 23);
        SecurityTest.getContentPane().add(chkbxAlt);

        // JTextArea
        textArea_cnt = new JTextArea();
        textArea_cnt.setBounds(115, 186, 30, 18);
        textArea_cnt.setText("0");
        SecurityTest.getContentPane().add(textArea_cnt);

        textArea_ubound = new JTextArea();
        textArea_ubound.setToolTipText("Number of times the loop will run.");
        textArea_ubound.setText("0");
        textArea_ubound.setBounds(167, 186, 30, 18);
        SecurityTest.getContentPane().add(textArea_ubound);

        chkbxSaveCfg = new JCheckBox("saveCfg");
        chkbxSaveCfg.setEnabled(false);
        chkbxSaveCfg.setSelected(true);
        chkbxSaveCfg.setToolTipText("Set password alternately");
        chkbxSaveCfg.setBounds(310, 346, 75, 23);
        SecurityTest.getContentPane().add(chkbxSaveCfg);
        // chkbxSaveCfg.setVisible(false);

        chkbxA = new JCheckBox("A");
        chkbxA.setToolTipText("");
        chkbxA.setBounds(310, 222, 33, 23);
        SecurityTest.getContentPane().add(chkbxA);

        chkbxa = new JCheckBox("a");
        chkbxa.setToolTipText("");
        chkbxa.setBounds(340, 222, 33, 23);
        SecurityTest.getContentPane().add(chkbxa);

        chkbx0 = new JCheckBox("0");
        chkbx0.setToolTipText("");
        chkbx0.setBounds(310, 248, 33, 23);
        SecurityTest.getContentPane().add(chkbx0);

        chkbx_ = new JCheckBox("!");
        chkbx_.setToolTipText("");
        chkbx_.setBounds(340, 248, 33, 23);
        SecurityTest.getContentPane().add(chkbx_);

        textArea_prfSave = new JTextArea();
        textArea_prfSave.setColumns(10);
        textArea_prfSave.setBounds(54, 118, 155, 20);
        SecurityTest.getContentPane().add(textArea_prfSave);

        JButton btnDirectory = new JButton("...");
        btnDirectory.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                prfDirectory = "";
                updateTextAreaPrf(prfDirectory, textArea_prfSave);
                JFileChooser j = new JFileChooser();
                j.setCurrentDirectory(new File("d:/"));
                j.setVisible(true);
                j.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                j.showDialog(new JLabel(), "Select");
                File file = j.getSelectedFile();
                if (file == null) {
                    prfDirectory = "";
                } else if (file.isDirectory()) {
                    prfDirectory = file.getAbsolutePath();
                    updateTextAreaPrf(prfDirectory, textArea_prfSave);
                }
            }
        });
        btnDirectory.setToolTipText("Directory to save PRF");
        btnDirectory.setBounds(10, 115, 42, 23);
        SecurityTest.getContentPane().add(btnDirectory);

        JButton btnGetPRF = new JButton("GetPRF");
        btnGetPRF.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (UserAuth) {
                    if ((!fwpwRunning) && (!digpwRunning) && (!fwRunning)) {
                        prfDirectory = textArea_prfSave.getText();
                        if (prfDirectory.equals("")) {
                            updateTextArea("Select a directory to store the file.\n");
                        } else {
                            debug = false;
                            prepare_prf("/downloadpasswordresetfile");
                            if (!tls) {
                                updateTextArea("Check tls checkbox before downloading SPRF.\n");
                            } else {
                                if (!sprfSegment) {
                                    updateTextArea("Start to download SPRF file.\n");
                                    enablePing();
                                    ResetPassword.download();
                                } else {
                                    updateTextArea("Start to download a cluster of SPRF files.\n");
                                    String[] str = textField_ip.getText().split("[.]");
                                    t_ping = new Timer();
                                    for (int i = Integer.parseInt(str[3]); i <= sprfEnd; i++) {
                                        enablePingForSeg(i);
                                    }
                                    ResetPassword.download();
                                }
                            }
                        }
                    } else {
                        updateTextArea("Other operation is in progress!! \n");
                    }
                } else {
                    updateTextArea("Input authorization code to enable the button.\n");
                }
            }
        });
        btnGetPRF.setToolTipText("Get PRF file");
        btnGetPRF.setBounds(210, 115, 86, 23);
        SecurityTest.getContentPane().add(btnGetPRF);

        textArea_prfUp = new JTextArea();
        textArea_prfUp.setColumns(10);
        textArea_prfUp.setBounds(54, 144, 155, 20);
        SecurityTest.getContentPane().add(textArea_prfUp);

        btnFile = new JButton("...");
        btnFile.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                // textArea_prfUp.setText("");
                updateTextAreaPrf("", textArea_prfUp);
                JFileChooser j = new JFileChooser();
                j.setCurrentDirectory(new File("d:/"));
                j.setVisible(true);
                j.setFileSelectionMode(JFileChooser.FILES_ONLY);
                j.showDialog(new JLabel(), "Select");
                File file = j.getSelectedFile();
                if (file == null) {
                    prfFileFromSelect = "";
                } else if (file.isFile()) {
                    prfFileFromSelect = file.getAbsolutePath();
                    updateTextAreaPrf(prfFileFromSelect, textArea_prfUp);
                }

            }
        });
        btnFile.setToolTipText("PRF file to upload");
        btnFile.setBounds(10, 141, 42, 23);
        SecurityTest.getContentPane().add(btnFile);

        btnResetPW = new JButton("RsPW");
        btnResetPW.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (UserAuth) {
                    if ((!fwpwRunning) && (!digpwRunning) && (!fwRunning)) {
                        prepare_prf("/resetpasswords");
                        enablePing();
                        debug = false;
                        prfFile = textArea_prfUp.getText();
                        if (prfFile.equals("")) {
                            updateTextArea("Reset DIGSI connection password...\n");
                            new ResetPassword().resetDigPw();
                        } else {
                            updateTextArea("Reset DIGSI connection and maintenance password...\n");
                            new ResetPassword().upload();
                        }
                    } else {
                        updateTextArea("Other operation is in progress!! \n");
                    }
                } else {
                    updateTextArea("Input authorization code to enable the button.\n");
                }
            }
        });
        btnResetPW.setToolTipText("Reset Passwrods with PRF file");
        btnResetPW.setBounds(210, 141, 86, 23);
        SecurityTest.getContentPane().add(btnResetPW);

    }

    private static void buildTextArea() {
        textArea = new JTextArea();
        JScrollPane js = new JScrollPane(textArea);
        js.setBounds(10, 230, 300, 170);
        SecurityTest.getContentPane().add(js);

        DefaultCaret caret = (DefaultCaret) textArea.getCaret(); // 这两行让文本框的滚动条自动在最下面.
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        textArea.setLineWrap(true); // 自动换行
        textArea.setWrapStyleWord(true);

        js.setVisible(true);
    }

    public static void exit() {
        if (save && (SetPassword.bw != null)) {
            try {
                SetPassword.bw.flush();
                SetPassword.bw.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
        saveCfg();
        System.exit(0);
    }

    public static Cfg readCfg() {
        File cfgfile = new File("SecurityTest.cfg");
        Cfg cfg = null;
        if (cfgfile.exists()) {
            ObjectInputStream ois;
            try {
                ois = new ObjectInputStream(new FileInputStream(cfgfile));
                cfg = (Cfg) ois.readObject();
                UserAuthPermanant = cfg.userAuthed;
                userInput = cfg.userID;
                chkbx0.setSelected(cfg.char0);
                chkbx_.setSelected(cfg.char_);
                chkbxA.setSelected(cfg.charA);
                chkbxa.setSelected(cfg.chara);
                textField_ip.setText(cfg.ip);
                textField_end.setText(cfg.ipEnd);
                textField_DigPW.setText(cfg.digpw);
                textField_MntPw.setText(cfg.mntpw);
                textField_period.setText(cfg.prid);
                textField_fw.setText(cfg.fw);
                textArea_prfSave.setText(cfg.dirPrfdown);
                textArea_prfUp.setText(cfg.dirPrfup);
                chkbxsave.setSelected(cfg.save);
                chkbxTls.setSelected(cfg.tls);
                chkbxAlt.setSelected(cfg.alter);
                rdbtnTCPOff.setSelected(cfg.tcpN);
                rdbtnTCPOn.setSelected(cfg.tcpY);
                rdbtnDTLSOn.setSelected(cfg.dtlsY);
                rdbtnDTLSOff.setSelected(cfg.dtlsN);
                rdbtnD.setSelected(cfg.digp);
                rdbtnF.setSelected(cfg.fwp);
                chkbxSaveCfg.setSelected(cfg.saveCfg);
                ois.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
        return cfg;
    }

    /**
     * 保存当前配置。不管勾不勾选savecfg，都会保存，只是保存的内容不同。
     */
    public static void saveCfg() {
        Cfg cfg = new Cfg();
        // cfg.userID = v.encode(user);
        // 如果勾选了saveCfg,就把所有配置都读一下，后面再存起来。
        if (chkbxSaveCfg.isSelected()) {
            cfg.userAuthed = UserAuthPermanant;
            cfg.userID = userInput;
            cfg.saveCfg = true;
            cfg.char0 = chkbx0.isSelected();
            cfg.char_ = chkbx_.isSelected();
            cfg.charA = chkbxA.isSelected();
            cfg.chara = chkbxa.isSelected();
            cfg.ip = textField_ip.getText();
            cfg.ipEnd = textField_end.getText();
            cfg.digpw = textField_DigPW.getText();
            cfg.mntpw = textField_MntPw.getText();
            cfg.prid = textField_period.getText();
            cfg.fw = textField_fw.getText();
            cfg.dirPrfdown = textArea_prfSave.getText();
            cfg.dirPrfup = textArea_prfUp.getText();
            cfg.save = chkbxsave.isSelected();
            cfg.tls = chkbxTls.isSelected();
            cfg.alter = chkbxAlt.isSelected();
            cfg.tcpN = rdbtnTCPOff.isSelected();
            cfg.tcpY = rdbtnTCPOn.isSelected();
            cfg.dtlsY = rdbtnDTLSOn.isSelected();
            cfg.dtlsN = rdbtnDTLSOff.isSelected();
            cfg.digp = rdbtnD.isSelected();
            cfg.fwp = rdbtnF.isSelected();
        } else {
            // 如果没有勾选saveCfg，就把之前已经保存的配置读出来，把cfg.savecfg这一项改了，后面再存起来。
            // 如果这是头一次打开，即还没有生成过配置文件，那就读不到东西，则关掉再打开会清掉最开始的默认配置（因为不管勾不勾选saveCfg，都会保存，
            // 只是保存策略不同），所以对Cfg类的每个字段赋初值。
            File cfgfile = new File("SecurityTest.cfg");
            if (cfgfile.exists()) {
                cfg = readCfg();
                cfg.saveCfg = false;
            }
        }
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("SecurityTest.cfg"));
            oos.writeObject(cfg);
            oos.flush();
            oos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void updateTextArea(String str) {
        textArea.append(str);
        textArea.paintImmediately(textArea.getBounds()); // 让更新立刻显示在界面上而不是等swing的主线程返回后刷新.
    }

    public static void updateTextAreaPrf(String str, JTextArea area) {
        // area.append(str);
        area.setText(str);
        area.paintImmediately(area.getBounds());
    }

    public static void updateTextAreacnt(int i) {
        textArea_cnt.setText(Integer.toString(i));
    }

    public static boolean prepare_traverse(/* Charset cs */) {
        int i = 0;
        traverse = false;
        turn = false;
        traverseA = chkbxA.isSelected();
        traversea = chkbxa.isSelected();
        traverse0 = chkbx0.isSelected();
        traverse_ = chkbx_.isSelected();
        if (traversea) {
            ubound = 26;
            charset = Charset.low;
            i++;
            traverse = true;
        }
        if (traverseA) {
            ubound = 26;
            charset = Charset.upp;
            i++;
            traverse = true;
        }
        if (traverse0) {
            ubound = 10;
            charset = Charset.dig;
            i++;
            traverse = true;
        }
        if (traverse_) {
            ubound = 33;
            charset = Charset.cha;
            i++;
            traverse = true;
        }
        if (i > 1) {
            // updateTextArea("Select at most 1 type.\n");
            // 如果想在这里调用reset()退出，没用。reset()执行完后会继续执行写密码的方法后面的部分。
            turn = true;
        }
        return turn;
    }

    /**
     * 识别输入的IP, PERIOD, 老密码. 密码后加五个星(*****)输出Log.
     */
    public static void prepare_setFwPW() {
        String str;
        String tmp;
        int len;
        save = chkbxsave.isSelected();
        tls = chkbxTls.isSelected();
        if (save)
            SetPassword.file = new File("Log_fwPw.txt");
        if (tls)
            host = "https://" + textField_ip.getText() + "/setmaintenancepassword";
        else
            host = "http://" + textField_ip.getText() + "/setmaintenancepassword";
        tmp = textField_period.getText();
        if (tmp.endsWith(".")) {
            tmp = tmp.substring(0, tmp.length() - 1);
            attack = true;
            updateTextArea("Password attempting:\n");
            // Common.pwExist = true; //既然要攻击，就认为密码存在。
        }
        period = Integer.parseInt(tmp);

        /* 周期为0时，两个密码框的字符串互为改密码时对方的目的密码 */
        ChangePw = false;
        if (period == 0) {
            SetPassword.target_password = textField_DigPW.getText();
            ChangePw = true;
        }
        /* 周期为0时，两个密码框的字符串互为改密码时对方的目的密码 */

        str = textField_MntPw.getText();
        commonpw = str;
        len = str.length();
        if (str.endsWith("*****")) {
            debug = true;
            mntpw = str.substring(0, len - 5);
        } else
            mntpw = str;
    }

    /**
     * 识别输入的IP, PERIOD, 老密码. 密码后加五个星(*****)输出Log.
     */
    public static void prepare_setDigPW() {
        String str;
        String tmp;
        save = chkbxsave.isSelected();
        tls = chkbxTls.isSelected();
        if (save)
            SetPassword.file = new File("Log_digsiPw.txt");
        int len;
        if (tls)
            host = "https://" + textField_ip.getText() + "/setconnectionpassword";
        else
            host = "http://" + textField_ip.getText() + "/setconnectionpassword";
        tmp = textField_period.getText();
        if (tmp.endsWith(".")) {
            tmp = tmp.substring(0, tmp.length() - 1);
            attack = true;
            updateTextArea("Password attempting:\n");
            // Common.pwExist = true; //既然要攻击，就认为密码存在。
        }
        period = Integer.parseInt(tmp);

        /* 周期为0时，两个密码框的字符串互为改密码时对方的目的密码 */
        ChangePw = false;
        if (period == 0) {
            SetPassword.target_password = textField_MntPw.getText();
            ChangePw = true;
        }
        /* 周期为0时，两个密码框的字符串互为改密码时对方的目的密码 */

        str = textField_DigPW.getText();
        commonpw = str;
        len = str.length();
        if (str.endsWith("*****")) {
            debug = true;
            digpw = str.substring(0, len - 5);
        } else
            digpw = str;
    }

    /**
     * 识别输入的IP, PERIOD, 老密码. 密码后加五个星(*****)输出Log.
     */
    public static void prepare_setNegPW() {
        String str;
        int len;
        save = chkbxsave.isSelected();
        tls = chkbxTls.isSelected();
        if (rdbtnD.isSelected()) {
            if (save)
                SetPassword.file = new File("Log_negdigsiPw.txt");
            if (tls)
                host = "https://" + textField_ip.getText() + "/setconnectionpassword";
            else
                host = "http://" + textField_ip.getText() + "/setconnectionpassword";
            period = Integer.parseInt(textField_period.getText());
            str = textField_DigPW.getText();
            commonpw = str;
            len = str.length();
            if (str.endsWith("*****")) {
                debug = true;
                digpw = str.substring(0, len - 5);
            } else
                digpw = str;
        }
        if (rdbtnF.isSelected()) {
            if (save)
                SetPassword.file = new File("Log_negfwPw.txt");
            if (tls)
                host = "https://" + textField_ip.getText() + "/setmaintenancepassword";
            else
                host = "http://" + textField_ip.getText() + "/setmaintenancepassword";
            period = Integer.parseInt(textField_period.getText());
            str = textField_MntPw.getText();
            commonpw = str;
            len = str.length();
            if (str.endsWith("*****")) {
                debug = true;
                mntpw = str.substring(0, len - 5);
            } else
                mntpw = str;
        }
    }

    /**
     * 识别输入的IP, PERIOD, FW 路径. 路径后加一个星(*),输出Log.
     */
    public static void prepare_upldFW() {
        String str;
        String end = textField_end.getText();
        if (end.startsWith(".")) {
            fwSegment = true;
            fwEnd = Integer.parseInt(end.substring(1, end.length()));
        } else {
            fwSegment = false;
        }
        int len;
        tls = chkbxTls.isSelected();
        if (tls)
            host = "https://" + textField_ip.getText() + "/upload";
        else
            host = "http://" + textField_ip.getText() + "/upload";
        period = Integer.parseInt(textField_period.getText());
        str = textField_fw.getText();
        len = str.length();
        if (str.endsWith("*")) {
            fw = str.substring(0, len - 1);
            debug = true;
        } else
            fw = str;
        mntpw = textField_MntPw.getText();
    }

    /**
     * 识别输入的IP. period为99时,输出Log.
     */
    public static void prepare_ChkCert() {
        String str = textField_ip.getText();
        String end = textField_end.getText();
        if (end.startsWith(".")) {
            certSegment = true;
            certEnd = Integer.parseInt(end.substring(1, end.length()));
        } else {
            certSegment = false;
        }
        save = chkbxsave.isSelected();
        tls = chkbxTls.isSelected();
        if (str.indexOf("https") == -1) {
            if (str.matches("[a-zA-Z]+")) { // 不玩了，GetCertificate.java里已去掉相关代码。
                ForFun = true;
                // ip = "https://www."+str+".com";
            } else {
                if (!tls) {
                    updateTextArea("Enable tls first.\n");
                } else {
                    ForFun = false;
                    // ip = "https://"+str+"/home";
                    host = textField_ip.getText();
                    period = Integer.parseInt(textField_period.getText());
                    if (period == 99)
                        debug = true;
                }
            }
        } else {
            ForFun = true;
            host = str;
        }
    }

    /**
     * 识别输入的IP，ctlVal. 密码后面跟五个星号，打开调试模式。
     */
    public static void prepare_TCP_DTLS(JRadioButton btnon, JRadioButton btnoff, String link) {
        String str = textField_MntPw.getText();
        int len = str.length();
        tls = chkbxTls.isSelected();
        if (tls)
            host = "https://" + textField_ip.getText() + link/* "/setupsecureengineeringaccess" */;
        else
            host = "http://" + textField_ip.getText() + link/* "/setupsecureengineeringaccess" */;
        if (str.endsWith("*****")) {
            debug = true;
            mntpw = str.substring(0, len - 5);
        } else
            mntpw = str;
        if (btnon.isSelected()) {
            ctlVal = 1;
        }
        if (btnoff.isSelected()) {
            ctlVal = 0;
        }
    }

    public static void prepare_prf(String link) {
        String end = textField_end.getText();
        if (end.startsWith(".")) {
            sprfSegment = true;
            sprfEnd = Integer.parseInt(end.substring(1, end.length()));
        } else {
            sprfSegment = false;
        }
        String str = textField_MntPw.getText();
        int len = str.length();
        tls = chkbxTls.isSelected();
        if (tls)
            host = "https://" + textField_ip.getText() + link/* "/downloadpasswordresetfile" */;
        else
            host = "http://" + textField_ip.getText() + link/* "/downloadpasswordresetfile" */;
        if (str.endsWith("*****")) {
            debug = true;
            mntpw = str.substring(0, len - 5);
        } else
            mntpw = str;
    }

    /**
     * 检查循环次数上限，读一个值，设一个标志位。输入数值以加号结尾时，返回true，让反向测试也用这个次数。否则只有正向测试用这个次数。
     * 
     * @return
     */
    public static boolean checkUbound() {
        String str = textArea_ubound.getText();
        boolean result = false;
        if (str.endsWith("+")) {
            result = true;
            str = str.substring(0, str.length() - 1);
        }
        ubound = Integer.parseInt(str);
        return result;
    }

    /**
     * Encapsulate Reset to a method. Facilitate calling.
     */
    public static void reset() {
        // reset = true;
        serverLost = false;
        traverse = false;
        if (t_ping_running) {
            t_ping.cancel();
            t_ping_running = false;
        }
        if (save && (SetPassword.streamClosed == false) && (fwpwRunning || digpwRunning || negRunning)) {
            try {
                while (!SetPassword.end) {
                    Thread.sleep(100);
                }
                SetPassword.bw.flush();
                SetPassword.bw.close();
                SetPassword.streamClosed = true;
                SetPassword.bw = null;
            } catch (IOException e1) {
                e1.printStackTrace();
            } catch (InterruptedException e1) {
                e1.printStackTrace();
            }
        }
        SetPassword.succ = 0;
        HttpPost.suc = 0;
        ubound = 0;

        if (fwRunning) {
            fwRunning = false;
            if (HttpPost.t != null) {
                HttpPost.t.cancel();
                HttpPost.t_running = false;
            }
        }
        if (fwpwRunning || digpwRunning) {
            fwpwRunning = false;
            digpwRunning = false;
            // 如果只用t.cancel()，则计时器被取消，本次是最后一次。但本次还是会运行下去，可能会与预期不同。
            stopped = true;
            if (SetPassword.t != null) {
                SetPassword.t.cancel();
                SetPassword.t_running = false;
            }
        }
        if (thread_neg != null) {
            negRunning = false;
            negative = false;
            // if(SetPassword.t != null)
            // SetPassword.t.cancel();
            stopped = true;
        }

        /* 下面这段可以获得当前所有运行的线程，本来是因为新建了很多timer去分别ping不同的装置，后来只用一个timer，所以这段没用到 */
        /*
         * ThreadGroup group = Thread.currentThread().getThreadGroup(); int number =
         * group.activeCount(); Thread[] threads = new Thread[number];
         * group.enumerate(threads); for(int i = 0; i < number; i++) {
         * System.out.println(i+" = "+threads[i].getName()); }
         */
    }

    public static String getIP(String src, Optype type) {
        String str = null;
        if (tls) {
            switch (type) {
            case digsi:
                str = "https://" + src + "/setconnectionpassword";
                break;
            case fw:
                str = "https://" + src + "/setmaintenancepassword";
                break;
            }
        } else {
            switch (type) {
            case digsi:
                str = "http://" + src + "/setconnectionpassword";
                break;
            case fw:
                str = "http://" + src + "/setmaintenancepassword";
                break;
            }
        }
        return str;
    }

    private static void enablePing() {
        if (!t_ping_running) {
            t_ping = new Timer();
            t_ping.schedule(window.new Ping(FrameSecurity.textField_ip.getText()), 0, 5000);
            t_ping_running = true;
        }
    }

    private void enablePingForSeg(int s) {
        String[] ip = textField_ip.getText().split("[.]");
        t_ping.schedule(window.new Ping(FrameSecurity.textField_ip.getText(), s - Integer.parseInt(ip[3])), 0, 5000);
        t_ping_running = true;
    }

    class Thread_neg extends SetPassword implements Runnable {
        @Override
        public void run() {
            if (!stopped) {
                SetPassword.set();
            }
        }
    }

    class Ping extends TimerTask {

        private String ip = "";
        private boolean reverse = false;
        private boolean lost = true;

        public Ping(String ip) {
            this.ip = ip;
        }
        public Ping(String ip, int i) {
            String[] str = textField_ip.getText().split("[.]");
            this.ip = str[0] + "." + str[1] + "." + str[2] + "." + (Integer.parseInt(str[3]) + i);
        }
        public void run() {
            try {
                InetAddress server = InetAddress.getByName(ip);
                if (!server.isReachable(1000)) {
                    // 下一个IP段内所有装置的FW时，要对每个装置(server)分别ping,分别取lost的状态，所以不能用总的serverLost。之前碰到的问题是，
                    // Server lost和server is online的log乱打，因为是用serverLost判断的，每个线程都能改这个值，且影响到其它线程。
                    if (fwSegment) {
                        if (false == lost) {
                            reverse = true; // 只有在原来能ping通，现在ping不能时才算状态反转。
                        }
                        lost = true;
                        if (reverse) {
                            reverse = false;
                            updateTextArea("Server lost! " + ip + "\n");
                        }
                        if (SetPassword.t_running) {
                            SetPassword.t.cancel();
                            t_ping.cancel();
                        }
                    } else {
                        serverLost = true;
                        updateTextArea("Server lost!!! " + ip + "\n");
                    }
                    // 模拟真正下firmware过程，装置会重启，server lost不停。
                    /*
                     * if(HttpPost.t_running) { HttpPost.t.cancel(); }
                     */
                } else {
                    if (fwSegment) {
                        if (lost) {
                            reverse = true;
                        }
                        lost = false;
                        if (reverse) {
                            reverse = false;
                            updateTextArea("Server is online! " + ip + "\n");
                        }
                    } else {
                        if (serverLost) { // 只有在从ping不通到ping通的变化时，才会打印server is online.
                            serverLost = false;
                            updateTextArea("Server is online!! " + ip + "\n");
                        }
                    }

                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

class Cfg implements Serializable {
    private static final long serialVersionUID = 1L;
    // 字段要赋初值，不然在第一次打开且时未勾选savecfg即关闭的情况下，再打开，会清掉所有配置
    String userID = null;
    String ip = "172.20.1.80";
    String ipEnd = "82";
    String digpw = "1!qQ1111";
    String mntpw = "1!qQ1111";
    String fw = "D:\\IEC61850_81.pck";
    String dirPrfdown;
    String dirPrfup;
    String prid = "3000";
    boolean userAuthed = false;
    boolean tcpY = false;
    boolean tcpN = false;
    boolean dtlsY = false;
    boolean dtlsN = false;
    boolean charA = false;
    boolean chara = false;
    boolean char0 = false;
    boolean char_ = false;
    boolean save = false;
    boolean tls = true;
    boolean alter = false;
    boolean neg;
    boolean fwp = true; // negtiv
    boolean digp = false; // negtiv
    boolean saveCfg = false;
}