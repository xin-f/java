package compareProj;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

public class Cmp {

    static List<Unit> Left = new ArrayList<>(200);
    static List<Unit> Right = new ArrayList<>(200);
    public int rD, rS, rL, rR; //different,same,left,right
    /**
     * 用于比较两个文件夹里面的内容，把结果写到excel。包含：同名且内容相同的文件，同名但内容不同的文件，以及各自独有的文件。 文件名包含最后一层文件夹，
     * 即...\folder1\src.c 和...folder2\src.c 认为不是同一个文件。
     * @param L 第一个待比较的文件夹
     * @param R 第二个待比较的文件夹
     */
    public void cmp(String L, String R) {
        File leftSrc = new File(L);
        File rightSrc = new File(R);
        String sheetNameL = L.substring(L.lastIndexOf('\\')+1)+" only";
        String sheetNameR = R.substring(R.lastIndexOf('\\')+1)+" only";
        int currentDepthL = 0;
        String s = leftSrc.toString();
        while (s.indexOf('\\') > 0) {
            currentDepthL++;
            s = s.substring(s.indexOf('\\') + 1);
        }
        int currentDepthR = 0;
        s = rightSrc.toString();
        while (s.indexOf('\\') > 0) {
            currentDepthR++;
            s = s.substring(s.indexOf('\\') + 1);
        }
        if (leftSrc.exists() && rightSrc.exists()) {
            lookup(leftSrc, Left, currentDepthL);
            lookup(rightSrc, Right, currentDepthR);
        }
        // Iterator<Unit> iterL = Left.iterator();
        // Iterator<Unit> iterR = Right.iterator();
        // Unit u;
        // while (iterL.hasNext()) {
        // u = iterL.next();
        // System.out.println(u);
        // iterL.remove();
        // }
        File file = new File("result.xlsx");
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            // fis = new FileInputStream(file);
            file.createNewFile();
            XSSFWorkbook workbook = new XSSFWorkbook();
            Sheet stS = workbook.createSheet("same");
            Sheet stD = workbook.createSheet("diff");
            Sheet stL = workbook.createSheet(sheetNameL);
            Sheet stR = workbook.createSheet(sheetNameR);
            BufferedReader brL = null, brR = null;
            Row row = null;
            Cell cell = null;
            for (Unit uL : Left) {  //以左侧的某个文件为目标，遍历右侧找同名的。所以右侧一旦找到了，要及时从列表中remove（）掉。件
                boolean uLprinted = false;
                boolean found = false; // 在另一侧找到同名的
                for (Unit uR : Right) {
                    if (uL.name.equals(uR.name)) { // 检查同名的
                        found = true;
                        brL = new BufferedReader(new InputStreamReader(new FileInputStream(uL.path.toString())));
                        brR = new BufferedReader(new InputStreamReader(new FileInputStream(uR.path.toString())));
                        String str;
                        while ((str = brL.readLine()) != null) {
                            if (!str.equals(brR.readLine())) {
                                row = stD.createRow(rD++);  //注意这里的行以及单元格都不是物理上的（即在excel里直接可见的），而是必须要先create出来，然后才能用。
                                //同名，内容不一样。匹配成功，两个文件分别打印出来。置为true，表示已经被输出。
                                cell = row.createCell(0);
                                cell.setCellValue(uL.path.toString());
                                uLprinted = true;       
                                cell = row.createCell(1);
                                cell.setCellValue(uR.path.toString());
                                Right.remove(uR);   //匹配到的移走。
                                break;
                            }
                        }
                        if (!uLprinted) {
                            //同名，且未被打印，表示内容一样。
                            row = stS.createRow(rS++);
                            cell = row.createCell(0);
                            cell.setCellValue(uL.path.toString());
                            cell = row.createCell(1);
                            cell.setCellValue(uR.path.toString());

                            Right.remove(uR);   //匹配到的移走。
                        }
                        break;
                    }
                }
                if (!found) {
                    //没找到，即只在左侧的列表存在的文件。
                    row = stL.createRow(rL++);
                    cell = row.createCell(0);
                    cell.setCellValue(uL.path.toString());
                }
            }
            for (Unit uR : Right) {
                //左边的列表已经找完了，右边的列表里被匹配的也已经remove了。右边的列表里剩下的就是只在右边存在的，打出来即可。
                row = stR.createRow(rR++);
                cell = row.createCell(0);
                cell.setCellValue(uR.path.toString());
            }
            workbook.write(fos);
            workbook.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 查找所有文件，放到一个文件列表里。有多层目录时递归调用。
     * @param f:        最初指定的包含所有待比较文件的总路径。即当作根目录。
     * @param list:     用来容纳所有文件的列表
     * @param currentDepth:   第一个参数f指定的路径的深度。实际查找到的文件的路径深度跟它一样，则查到的文件是根目录的，否则一层层累加，记下路径层数，最终为了记下全路径。
     */
    static void lookup(File f, List<Unit> list, int currentDepth) {
        File[] tmp = f.listFiles();
        for (File file : tmp) {
            Unit unit = new Unit();
            if (file.isDirectory()) {
                unit.depth++;
                lookup(file, list, currentDepth);
            } else {
                int currentD = 0;
                String s = file.toString();
                while (s.indexOf('\\') > 0) {
                    currentD++;
                    s = s.substring(s.indexOf('\\') + 1);
                }
                int index = file.toString().lastIndexOf('\\');
                unit.route = file.toString().substring(0, index);
                int depth = currentD - currentDepth;
                if (depth > 1) {
                    String str = unit.route.substring(unit.route.lastIndexOf('\\'));
                    unit.name = str + "\\" + file.toString().substring(index + 1);
                } else {
                    unit.name = file.toString().substring(index + 1);
                }
                unit.path = Paths.get(file.toString());
                System.out.println(unit.path + "  |  " + unit.name);
                list.add(unit);
            }
        }
    }
}

//每个具体的文件为一个Unit
class Unit {
    String route;
    Path path;
    String name; // 文件名包含最后一层文件目录
    int depth = 0;
    public String toString() {
        return route + "\\" + name;
    }
}