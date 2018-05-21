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
    public int rD, rS, rL, rR;
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
            show(leftSrc, Left, currentDepthL);
            show(rightSrc, Right, currentDepthR);
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
            for (Unit uL : Left) {
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
                                cell = row.createCell(0);
                                cell.setCellValue(uL.path.toString());
                                uLprinted = true;
                                cell = row.createCell(1);
                                cell.setCellValue(uR.path.toString());
                                Right.remove(uR);
                                break;
                            }
                        }
                        if (!uLprinted) {
                            row = stS.createRow(rS++);
                            cell = row.createCell(0);
                            cell.setCellValue(uL.path.toString());
                            cell = row.createCell(1);
                            cell.setCellValue(uR.path.toString());

                            Right.remove(uR);
                        }
                        break;
                    }
                }
                if (!found) {
                    row = stL.createRow(rL++);
                    cell = row.createCell(0);
                    cell.setCellValue(uL.path.toString());
                }
            }
            for (Unit uR : Right) {
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

    static void show(File f, List<Unit> list, int currentDepth) {
        File[] tmp = f.listFiles();
        for (File file : tmp) {
            Unit unit = new Unit();
            if (file.isDirectory()) {
                unit.depth++;
                show(file, list, currentDepth);
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

class Unit {

    String route;
    Path path;
    String name; // 文件名包含最后一层文件目录
    int depth = 0;
    public String toString() {
        return route + "\\" + name;
    }
}