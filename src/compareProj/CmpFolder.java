package compareProj;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;

public class CmpFolder {

    private JFrame frame;
    private String routeL;
    private String routeR;
    JTextArea ta_routeL;
    JTextArea ta_routeR;
    private JLabel lbS;
    private JTextArea taS;
    private JLabel lbD;
    private JTextArea taD;
    private JLabel lbL;
    private JTextArea taL;
    private JTextArea taR;
    private JLabel lbR;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    CmpFolder window = new CmpFolder();
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Create the application.
     */
    public CmpFolder() {
        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize() {
        frame = new JFrame();
        frame.setBounds(100, 100, 300, 280);
        frame.setTitle("Cmpr folder");
        frame.setResizable(false);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(null);
        
        JButton btnSelRouteL = new JButton("...");
        btnSelRouteL.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                routeL = "";
                updateTextArea(routeL, ta_routeL);
                JFileChooser j = new JFileChooser();
                j.setCurrentDirectory(new File("d:/"));
                j.setVisible(true);
                j.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                j.showDialog(new JLabel(), "Select");
                File file = j.getSelectedFile();
                if (file == null) {
                    routeL = "";
                } else if (file.isDirectory()) {
                    routeL = file.getAbsolutePath();
                    updateTextArea(routeL, ta_routeL);
                }
            }

        });
        btnSelRouteL.setToolTipText("Directory to save PRF");
        btnSelRouteL.setBounds(10, 11, 42, 23);
        frame.getContentPane().add(btnSelRouteL);
        
        ta_routeL = new JTextArea();
        ta_routeL.setColumns(10);
        ta_routeL.setBounds(54, 14, 155, 20);
        frame.getContentPane().add(ta_routeL);
        
        JButton btnCmp = new JButton("Cmpr");
        btnCmp.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                String L = ta_routeL.getText();
                String R = ta_routeR.getText();
                Cmp c = new Cmp();
                c.cmp(L, R);
                updateTextArea(Integer.toString(c.rS), taS);
                updateTextArea(Integer.toString(c.rD), taD);
                updateTextArea(Integer.toString(c.rL), taL);
                updateTextArea(Integer.toString(c.rR), taR);
                
            }
        });
        btnCmp.setBounds(10, 73, 86, 23);
        frame.getContentPane().add(btnCmp);
        
        JButton btnSelRouteR = new JButton("...");
        btnSelRouteR.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                routeR = "";
                updateTextArea(routeR, ta_routeR);
                JFileChooser j = new JFileChooser();
                j.setCurrentDirectory(new File("d:/"));
                j.setVisible(true);
                j.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                j.showDialog(new JLabel(), "Select");
                File file = j.getSelectedFile();
                if (file == null) {
                    routeR = "";
                } else if (file.isDirectory()) {
                    routeR = file.getAbsolutePath();
                    updateTextArea(routeR, ta_routeR);
                }
            }
        });
        btnSelRouteR.setToolTipText("Directory to save PRF");
        btnSelRouteR.setBounds(10, 41, 42, 23);
        frame.getContentPane().add(btnSelRouteR);
        
        ta_routeR = new JTextArea();
        ta_routeR.setColumns(10);
        ta_routeR.setBounds(54, 41, 155, 20);
        frame.getContentPane().add(ta_routeR);
        
        lbS = new JLabel("Same:");
        lbS.setBounds(10, 107, 50, 22);
        frame.getContentPane().add(lbS);
        
        taS = new JTextArea();
        taS.setText("0");
        taS.setBounds(84, 107, 40, 18);
        frame.getContentPane().add(taS);
        
        lbD = new JLabel("Diff:");
        lbD.setBounds(10, 134, 50, 22);
        frame.getContentPane().add(lbD);
        
        taD = new JTextArea();
        taD.setText("0");
        taD.setBounds(84, 134, 40, 18);
        frame.getContentPane().add(taD);
        
        lbL = new JLabel("UpperOnly :");
        lbL.setBounds(10, 162, 70, 22);
        frame.getContentPane().add(lbL);
        
        taL = new JTextArea();
        taL.setText("0");
        taL.setBounds(84, 162, 40, 18);
        frame.getContentPane().add(taL);
        
        taR = new JTextArea();
        taR.setText("0");
        taR.setBounds(84, 188, 40, 18);
        frame.getContentPane().add(taR);
        
        lbR = new JLabel("LowerOnly :");
        lbR.setBounds(10, 188, 70, 22);
        frame.getContentPane().add(lbR);
    }

    private void updateTextArea(String route, JTextArea ta) {
        ta.setText(route);
    }
}
