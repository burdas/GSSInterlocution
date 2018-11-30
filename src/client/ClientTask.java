/*
 * @(#)ClientTask.java
 *
 * Copyright (c) 2001, 2002, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or 
 * without modification, are permitted provided that the following 
 * conditions are met:
 * 
 * -Redistributions of source code must retain the above copyright  
 * notice, this  list of conditions and the following disclaimer.
 * 
 * -Redistribution in binary form must reproduct the above copyright 
 * notice, this list of conditions and the following disclaimer in 
 * the documentation and/or other materials provided with the 
 * distribution.
 * 
 * Neither the name of Oracle or the names of 
 * contributors may be used to endorse or promote products derived 
 * from this software without specific prior written permission.
 * 
 * This software is provided "AS IS," without a warranty of any 
 * kind. ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND 
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE HEREBY 
 * EXCLUDED. SUN AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY 
 * DAMAGES OR LIABILITIES  SUFFERED BY LICENSEE AS A RESULT OF  OR 
 * RELATING TO USE, MODIFICATION OR DISTRIBUTION OF THE SOFTWARE OR 
 * ITS DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE 
 * FOR ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, 
 * SPECIAL, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER 
 * CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY, ARISING OUT OF 
 * THE USE OF OR INABILITY TO USE SOFTWARE, EVEN IF SUN HAS BEEN 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * You acknowledge that Software is not designed, licensed or 
 * intended for use in the design, construction, operation or 
 * maintenance of any nuclear facility. 
 */

package client;

import org.ietf.jgss.*;
import java.net.Socket;
import java.net.InetAddress;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.PrivilegedExceptionAction;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import JGSSSecureAssociation.JGSSSecureAssociation;

/**
 * A sample client application that uses JGSS to do mutual authentication with
 * a server using Kerberos as the underlying mechanism. It then exchanges data
 * securely with the server.
 *
 * Every message sent to the server includes a 4-byte application-level header
 * that contains the big-endian integer value for the number of bytes that will
 * follow as part of the JGSS token.
 *
 * The protocol is:
 *    1.  Context establishment loop:
 *         a. client sends init sec context token to server
 *         b. server sends accept sec context token to client
 *         ....
 *    2. client sends a wrap token to the server.
 *    3. server sends a MIC token to the client for the application
 *       message that was contained in the wrap token.
 */

final class ClientTask implements PrivilegedExceptionAction<Void> {
  
  static private final String CLASS_NAME = ClientTask.class.getName();
  static private final Logger LOGGER = Logger.getLogger(CLASS_NAME);

  // Parametros del servicio con el que se conecta  
  private final InetAddress serverIP;
  private final String service;
  private final int port;

  ClientTask (final String service, final InetAddress ip, final int port) {
    // Parametros del servicio con el que se conecta
    // En una implementación más profesional de la parte cliente de un servicio
    // concreto, estos valores se tomarían de un fichero de configuración,
    // de modo que no haya que recompilar el código de la parte cliente cuando
    // cambien la dirección IP o el puerto de escucha del servicio.
    this.serverIP = ip;
    this.service = service;
    this.port = port;
  }

  @Override
  public Void run () throws GSSException {

    final GSSManager manager = GSSManager.getInstance();

    /*
     * Create a GSSName out of the service's name. The null
     * indicates that this application does not wish to make
     * any claims about the syntax of this name and that the
     * underlying mechanism should try to parse it as per whatever
     * default syntax it chooses.
     */
    final Oid krb5PrincipalNameOid = new Oid("1.2.840.113554.1.2.2.1");
    final GSSName serviceName = manager.createName(service, krb5PrincipalNameOid);

    /*
     * This Oid is used to represent the Kerberos version 5 GSS-API
     * mechanism. It is defined in RFC 1964. We will use this Oid
     * whenever we need to indicate to the GSS-API that it must use
     * Kerberos for some purpose.
     */
    final Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");

    /*
     * Create a GSSContext for mutual authentication with the service.
     *    - serviceName is the GSSName that represents the service.
     *    - krb5Oid is the Oid that represents the mechanism to
     *      use. The client chooses the mechanism to use.
     *    - null is passed in for client credentials.
     *    - DEFAULT_LIFETIME lets the mechanism decide how long the
     *      context can remain valid.
     * Note: Passing in null for the credentials asks GSS-API to
     * use the default credentials. This means that the mechanism
     * will look among the credentials stored in the current Subject
     * to find the right kind of credentials that it needs.
     */
    final GSSContext context = manager.createContext(serviceName,
            krb5Oid,
            null,
            GSSContext.DEFAULT_LIFETIME);

    //
    // Set the desired optional features on the context.
    // The client chooses these options.
    //
    
    // Mutual authentication
    // https://docs.oracle.com/javase/7/docs/api/org/ietf/jgss/GSSContext.html#requestMutualAuth(boolean)
    context.requestMutualAuth(true);
    // Will use confidentiality later
    // https://docs.oracle.com/javase/7/docs/api/org/ietf/jgss/GSSContext.html#requestConf(boolean)
    context.requestConf(true);
    // Will use integrity later
    // https://docs.oracle.com/javase/7/docs/api/org/ietf/jgss/GSSContext.html#requestInteg(boolean)
    context.requestInteg(true);

    // Interaction with service
    try (final Socket socket = new Socket(serverIP, port)) {
      
      try /*(/*final DataInputStream  is = new DataInputStream(socket.getInputStream()); 
              final DataOutputStream os = new DataOutputStream(socket.getOutputStream()))*/ {

        System.out.println("Connected to server " + socket.getInetAddress());

        JGSSSecureAssociation jgss = new JGSSSecureAssociation(context);
        jgss.init(socket.getInputStream(), socket.getOutputStream(), true, true);

        System.out.println("  * GSS context established! ");
        System.out.println("  * Client  is " + context.getSrcName());
        System.out.println("  * Service is " + context.getTargName());

        /*
         * If mutual authentication did not take place, then only the
         * client was authenticated to the server. Otherwise, both
         * client and server were authenticated to each other.
         */
        if (context.getMutualAuthState()) {
          System.out.println("  * Mutual authentication took place!");
        }

        final String message;
        try (final Scanner scanner = new Scanner(System.in)) {
          System.out.print("Introduce mensaje a enviar: ");
          message = scanner.nextLine();
        }
        
        /*
         * The first MessageProp argument is 0 to request
         * the default Quality-of-Protection.
         * The second argument is true to request
         * privacy (encryption of the message).
         */
        jgss.send(message, true);
        
        

        /*
         * Encrypt the data and send it across. Integrity protection is
         * always applied, irrespective of confidentiality (i.e., encryption).
         */
        

        /*
         * Now we will allow the server to decrypt the message, calculate
         * a MIC on the decrypted message and send it back to us for verification.
         * This is unnecessary, but done here for illustration.
         */
        

        System.out.println("  * Verified received MIC for message.");
        System.out.println("Exiting...");

      } catch (final IOException ex) {
        LOGGER.log(Level.SEVERE, "Problem with socket:", ex);
      } catch (final GSSException ex) {
        LOGGER.log(Level.SEVERE, "Problem with context:", ex);
      }
      
    } catch (final IOException ex) {
      LOGGER.log(Level.SEVERE, "Error opening socket:", ex);
    } catch (final SecurityException ex) {
      LOGGER.log(Level.SEVERE, "Operation not allowed:", ex);
    } finally {
      try {
        context.dispose();
      } catch (final GSSException ex) {
        LOGGER.log(Level.SEVERE, "Problem at context dispose:", ex);
      }
    }

    return null;

  }
    
}