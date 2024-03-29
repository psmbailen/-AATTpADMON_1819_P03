import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;


/**
 * Aplicaciones Telemáticas para la Administración
 * 
 * Este programa debe leer el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a través de HTTP 
 * @author Juan Carlos Cuevas Martínez
 */
public class Main {
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        ByteArrayInputStream bais=null;
        
        //TAREA 2. Conseguir que el método LeerNIF de ObtenerDatos devuelva el 
        //         correctamente los datos de usuario 
        ObtenerDatos od = new ObtenerDatos();
        Usuario user = od.LeerNIF();
        if(user!=null)
            System.out.println("usuario: "+user.toString());
        //hola
        //TAREA 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR

        /*
Class Autentica->Cliente

public String EnviarPost(String urlpost,String user,...){
    String postparam="user"+ user+ "&dni"+...
    inputstream is =null;
    String result= null;
    HttpConnection conn=null;
}

respuesta=enlace.noseque(Http:Direccion Ip:Puerto: Directorio)

public class autentica extends HttpServlet{
    --user
    --dni
    protected void processRequest (HttpServlets request, HttpServlet... response){

        "Busqueda en la base de datos
{HTML}

}
protected void doPost

}
*/
    }
}
