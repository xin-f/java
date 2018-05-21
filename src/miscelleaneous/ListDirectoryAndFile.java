package miscelleaneous;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.stream.Stream;

public class ListDirectoryAndFile {
    
    public static void main(String[] args) throws NoSuchMethodException, SecurityException {
        Path dir = Paths.get(".");
        try(DirectoryStream<Path> stream = Files.newDirectoryStream(dir)){
            for(Path e : stream){
                System.out.println(e.getFileName());
            }
        }catch(IOException e){
            
        }
        System.out.println("---------------");
        try (Stream<Path> stream = Files.list(Paths.get("d:\\"))){
            Iterator<Path> ite = stream.iterator();
            while(ite.hasNext()){
                Path pp = ite.next();
                System.out.println(pp.getFileName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
       
    }
}