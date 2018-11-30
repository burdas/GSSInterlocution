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

import java.io.IOException;
import java.net.ServerSocket;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;


final class DossierBox implements PrivilegedExceptionAction<Void> {

  static private final String SERVICE_NAME = "dossierbox";
  
  static private final String CLASS_NAME = DossierBox.class.getName();
  static private final Logger LOGGER = Logger.getLogger(CLASS_NAME);  
    
  // Servicio ejecutor para atender solicitudes entrantes.
  final ExecutorService executorForServiceTasks;
  // Puerto de escucha del servicio
  private final int servicePortNumber;
  
  DossierBox (final int port, final int numThreads) {
    // Parametros de operación.
    // En una implementación más profesional de la parte cliente de un servicio
    // concreto, estos valores se tomarían de un fichero de configuración,
    // de modo que no haya que recompilar el código de la parte cliente cuando
    // cambien la dirección IP o el puerto de escucha del servicio.    
    this.servicePortNumber = port;
    // El valor numThreads indica el número máximo de clientes
    // que van a poder ser atendidos simultánemamente.
    this.executorForServiceTasks = Executors.newFixedThreadPool(numThreads);
  }

  @Override
  public Void run () throws IOException, SecurityException {
    
    final ServerSocket serverSocket;
    try {
      serverSocket = new ServerSocket(servicePortNumber);
    } catch (final IOException ex) {
      LOGGER.log(Level.SEVERE,"Problem creating server socket:", ex);
      throw new IOException();
    } catch (final SecurityException ex) {
      LOGGER.log(Level.SEVERE, "Permission denied:", ex);
      throw new SecurityException();
    }

    System.out.println("Waiting for incomings connection...");
    while (true) {

      final ServerTask task =
              new ServerTask(serverSocket.accept());
      System.out.println("New incoming connection");
      executorForServiceTasks.submit(task);

    }

  }

}