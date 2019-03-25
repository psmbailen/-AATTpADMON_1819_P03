import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.*;

/**
 * La clase ObtenerDatos implementa cuatro métodos públicos que permiten obtener
 * determinados datos de los certificados de tarjetas DNIe, Izenpe y Ona.
 *
 * @author tbc
 */
public class ObtenerDatos {

    private static final byte[] dnie_v_1_0_Atr = {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44,
        (byte) 0x4E, (byte) 0x49, (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00};
    private static final byte[] dnie_v_1_0_Mask = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};

    public ObtenerDatos() {
    }

    public Usuario LeerNIF() {

        Usuario user = null;
        byte[] datos=null;
        try {
            Card c = ConexionTarjeta();
            if (c == null) {
                throw new Exception("ACCESO DNIe: No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                datos = leerCertificado(ch);
                if(datos!=null)
                    user = leerDatosUsuario(datos);
            }
            c.disconnect(false);

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return user;
    }

    public byte[] leerCertificado(CardChannel ch) throws CardException, CertificateException {


        int offset = 0;
        String completName = null;

        //[1] PRÁCTICA 3. Punto 1.a
        /*Todos son el comando SELECT. Este comando permite la seleccion de fichero dedicado a (DF) o de un fichero elemental (EF). 
        Esto lo sabemos ya que en el siguiente array de bytes tiene la misma estructura que el comando APDU de la guía de comandos
        - El primer octeto 0x00 es el campo CLA
        - El segundo octeto 0xA4 es el campo INS
        - El tercero octeto  es el campo P1. Puede ser 0x00(Selecciona DF o EF por Id) o 0x04(Seleccion directa de DF por nombre)
        - El cuarto octeto es 0x00 es el campo P2.
        - El quinto octeto es el campo LC, es la longitud del campo de datos.
        - El sexto octeto son los datos de acuerdo a P1-P2.
        - El séptimo octeto es el campo LE que esta vacío
       */ 
      
        byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
        /* 
        En este caso P1 es 0x04
        LC es 0x0b
        Los datos son: 4D 61 73 74 65 72 2E 46 69 6C 65 en formato hexadecimal
        Si lo pasamos a ASCII ya que P1 selecciona por nombr nos sale que significa Master.File que es un comando de seleción por nombre del fichero maestro
        */
        ResponseAPDU r = ch.transmit(new CommandAPDU(command));
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[2] PRÁCTICA 3. Punto 1.a
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
        /*
        En este caso P1 es 0x00
        LC es 0x02
        Los datos son: 50 15
        Si lo pasamos a decimal ya que P1 seleccionar por ID nos sale el número 80 que es el ID del fichero
        */
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[3] PRÁCTICA 3. Punto 1.a
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
          /*
        En este caso P1 es 0x00
        LC es 0x02
        Los datos son: 60 04
        Si lo pasamos a decimal ya que P1 seleccionar por ID nos sale el número 96 que es el ID del fichero
        
        */
        r = ch.transmit(new CommandAPDU(command));
        
        byte[] responseData = null;
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        } else {
            responseData = r.getData();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] r2 = null;
        int bloque = 0;

        do {
             //[4] PRÁCTICA 3. Punto 1.b OJO
            
            /* Es el comando Read Binary cuyo comando devuelve en su mensaje de respuesta el contenido (o parte) de
        	un fichero elemental transparente.
            */
            final byte CLA = (byte) 0x00;//Este valor puede variar desde 0x00 hasta 0x0F
            final byte INS = (byte) 0xB0;//
            final byte LE = (byte) 0xFF;/*Es el campo LE que es el número de bytes a leer.
                                         Si el campo Le=0 el número de bytes a leer es 256. 
            				En este caso vale 255 porque FF=255 si lo pasamos a decimal			*/

            //[4] PRÁCTICA 3. Punto 1.b
            command = new byte[]{CLA, INS, (byte) bloque/*P1*/, (byte) 0x00/*P2*/, LE};//Identificar qué hacen P1 y P2
            //P1 y P2 son el offsert del primer byte a leer desde el principio del fichero
            r = ch.transmit(new CommandAPDU(command));

            //System.out.println("ACCESO DNIe: Response SW1=" + String.format("%X", r.getSW1()) + " SW2=" + String.format("%X", r.getSW2()));

            if ((byte) r.getSW() == (byte) 0x9000) {
                r2 = r.getData();

                baos.write(r2, 0, r2.length);

                for (int i = 0; i < r2.length; i++) {
                    byte[] t = new byte[1];
                    t[0] = r2[i];
                    System.out.println(i + (0xff * bloque) + String.format(" %2X", r2[i]) + " " + String.format(" %d", r2[i])+" "+new String(t));
                    
                }
                bloque++;
            } else {
                return null;
            }

        } while (r2.length >= 0xfe);


         ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

      

        
        return baos.toByteArray();
    }

    
    
    
    /**
     * Este método establece la conexión con la tarjeta. La función busca el
     * Terminal que contenga una tarjeta, independientemente del tipo de tarjeta
     * que sea.
     *
     * @return objeto Card con conexión establecida
     * @throws Exception
     */
    private Card ConexionTarjeta() throws Exception {

        Card card = null;
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        //System.out.println("Terminals: " + terminals);

        for (int i = 0; i < terminals.size(); i++) {

            // get terminal
            CardTerminal terminal = terminals.get(i);

            try {
                if (terminal.isCardPresent()) {
                    card = terminal.connect("*"); //T=0, T=1 or T=CL(not needed)
                }
            } catch (Exception e) {

                System.out.println("Exception catched: " + e.getMessage());
                card = null;
            }
        }
        return card;
    }

    /**
     * Este método nos permite saber el tipo de tarjeta que estamos leyendo del
     * Terminal, a partir del ATR de ésta.
     *
     * @param atrCard ATR de la tarjeta que estamos leyendo
     * @return tipo de la tarjeta. 1 si es DNIe, 2 si es Starcos y 0 para los
     * demás tipos
     */
    private boolean esDNIe(byte[] atrCard) {
        int j = 0;
        boolean found = false;

        //Es una tarjeta DNIe?
        if (atrCard.length == dnie_v_1_0_Atr.length) {
            found = true;
            while (j < dnie_v_1_0_Atr.length && found) {
                if ((atrCard[j] & dnie_v_1_0_Mask[j]) != (dnie_v_1_0_Atr[j] & dnie_v_1_0_Mask[j])) {
                    found = false; //No es una tarjeta DNIe
                }
                j++;
            }
        }

        if (found == true) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Analizar los datos leídos del DNIe para obtener
     *   - nombre
     *   - apellidos
     *   - NIF
     * @param datos
     * @return 
     */
    private Usuario leerDatosUsuario(byte[] datos) {
       return null;
    }
}


