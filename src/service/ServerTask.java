/*
 * @(#)ServiceOn.java
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

package service;

import org.ietf.jgss.*;
import java.io.*;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import JGSSSecureAssociation.JGSSSecureAssociation;

/**
 * A sample server application that uses JGSS to do mutual authentication with
 * a client using Kerberos as the underlying mechanism. It then exchanges data
 * securely with the client.
 *
 * Every message exchanged with the client includes a 4-byte application-level
 * header that contains the big-endian integer value for the number of bytes
 * that will follow as part of the JGSS token.
 *
 * The protocol is:
 *    1.  Context establishment loop:
 *         a. client sends init sec context token to server
 *         b. server sends accept sec context token to client
 *         ....
 *    2. client sends a wrap token to the server.
 *    3. server sends a mic token to the client for the application
 *       message that was contained in the wrap token.
 */

final class ServerTask implements Runnable {
  
  static private final String CLASS_NAME = ServerTask.class.getName();
  static private final Logger LOGGER = Logger.getLogger(CLASS_NAME);
  
  final Socket socket; 

  ServerTask (final Socket socket) {
    this.socket  = socket;
  }

  @Override
  public void run () {

    try /*(final DataInputStream is  = new DataInputStream(socket.getInputStream());
         final DataOutputStream os = new DataOutputStream(socket.getOutputStream()))*/ {

      System.out.println("#############################################################");  
      System.out.println("* Got connection from client " + socket.getInetAddress());

      final GSSManager manager = GSSManager.getInstance();
      try {

        /*
         * Create a GSSContext to receive the incoming request 
         * from the client. Use null for the server credentials 
         * passed in. This tells the underlying mechanism
         * to use whatever credentials it has available that
         * can be used to accept this connection.
         */
        final GSSContext context = manager.createContext((GSSCredential) null);

        JGSSSecureAssociation jgss = new JGSSSecureAssociation(context);
        jgss.accept(socket.getInputStream(), socket.getOutputStream());

        System.out.println("  * GSS context established! ");
        System.out.println("  * Client  is " + context.getSrcName());
        System.out.println("  * Service is " + context.getTargName());

        /*
         * If mutual authentication did not take place, then
         * only the client was authenticated to the server.
         * Otherwise, both client and server were authenticated
         * to each other.	 
         */
        if (context.getMutualAuthState()) {
          System.out.println("  * Mutual authentication took place!");
        }

        /*
         * Create a MessageProp which unwrap will use to return 
         * information such as the Quality-of-Protection that was 
         * applied to the wrapped token, whether or not it was 
         * encrypted, etc. Since the initial MessageProp values
         * are ignored, just set them to the defaults of 0 and false.
         */
        
        final String str = jgss.receive();

        System.out.println("  * Received data \""
                + str + "\" of length " + str.length());

        //System.out.println("  * Confidentiality applied: "
        //        + prop.getPrivacy());


        /*
         * Now generate a MIC and send it to the client. This is
         * just for illustration purposes. The integrity of the
         * incoming wrapped message is guaranteed irrespective
         * of the confidentiality (encryption) that was used.
         */

        /*
         * First reset the QOP of the MessageProp to 0 to ensure
         * the default Quality-of-Protection is applied.
         */
        

      } catch (final GSSException ex) {
        LOGGER.log(Level.SEVERE, "Problem with GSSContext:", ex);
      }

      System.out.println("* closing connection with client "
              + socket.getInetAddress());
      System.out.println("#############################################################");        

    } catch (final IOException ex) {
      LOGGER.log(Level.SEVERE, "Problem with socket:", ex);
    } finally {
      try {
        socket.close();
      } catch (final IOException ex) {
        LOGGER.log(Level.SEVERE, "Problema at closing socket:", ex);
      }
      return;
    }

  }
  
}