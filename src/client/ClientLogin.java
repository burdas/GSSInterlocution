/*
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
 * Neither the name of Oracle nor the names of
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

import java.util.logging.Level;
import java.util.logging.Logger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import com.sun.security.auth.callback.TextCallbackHandler;

public final class ClientLogin {
  
  static private final String CLASS_NAME = ClientLogin.class.getName();
  static private final Logger LOGGER = Logger.getLogger(CLASS_NAME);
  
  static private final String SERVICE_NAME = "dossierbox";    

  static public void main (final String[] args) throws UnknownHostException {
    
    if (args.length != 1) {
      System.out.println("Usage: app <port>");
      return;
    }

    final int port = Integer.parseInt(args[0]);    

    final LoginContext lc;
    try {
      lc = new LoginContext("Client", new TextCallbackHandler());
    } catch (final LoginException ex) {
      System.err.println("No configuration entry to create specified LoginContext");
      return;
    } catch (final SecurityException ex) {
      System.err.println("No permission to create specified LoginContext");
      return;
    }
    
    try {

      // Attempt authentication
      lc.login();
      
      // Now try to execute the InteractionWithService as the authenticated Subject
      final Subject mySubject = lc.getSubject();
      final PrivilegedExceptionAction<Void> service
              = new ClientTask(SERVICE_NAME, InetAddress.getLocalHost(), port);
      try {
        Subject.doAsPrivileged(mySubject, service, null);
      } catch (final PrivilegedActionException ex) {
        System.err.println("Error executing privileged action");
      } catch (final SecurityException ex) {
        LOGGER.log(Level.SEVERE, ex.getMessage());
        System.err.println("No permission to execute privileged action");
      }
      
      try {
        lc.logout();
      } catch (final LoginException ex) {
        LOGGER.log(Level.SEVERE, "Cannot remove LoginContext:", ex);
      }
    
    } catch (final LoginException ex) {
      System.err.println("Authentication failed");
    }

    System.exit(0);

  }

}