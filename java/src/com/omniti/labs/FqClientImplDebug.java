/*
 * Copyright (c) 2013 OmniTI Computer Consulting, Inc.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

package com.omniti.labs;

import java.util.Date;
import java.util.Map;

public class FqClientImplDebug implements FqClientImplInterface {
  protected FqClient client = null;
  public void setClient(FqClient c) throws InUseException {
    if(client != null) throw new InUseException();
    client = c;
  }
  protected void genericError(Throwable e) {
    e.printStackTrace();
  }
  public void connectError(Throwable e) { genericError(e); } 
  public void commandError(Throwable e) { genericError(e); }
  public void dataError(Throwable e) { genericError(e); }
  public void dispatch(FqMessage m) {
    byte b[] = m.getPayload();
    int len = (b == null) ? 0 : b.length;
    System.err.println("m[" + len + "] via " + m.getRoute() +
      " over " + m.getExchange() + " from " + m.getSender());
  }
  public void dispatch(FqCommand cmd) {
    System.err.println(cmd);
  }
  public void dispatchAuth(FqCommand.Auth cmd) {
    dispatch(cmd);
  }
  public void dispatchHeartbeatRequest(FqCommand.HeartbeatRequest cmd) {
    dispatch(cmd);
  }
  public void dispatchHeartbeat(FqCommand.Heartbeat cmd) { dispatch(cmd); }
  public void dispatchBindRequest(FqCommand.BindRequest cmd) {
    System.err.println(cmd.toString() + cmd.getBinding());
  }
  public void dispatchUnbindRequest(FqCommand.UnbindRequest cmd) {
    System.err.println(cmd.toString() + cmd.getBinding() + " " + cmd.getSuccess());
  }
  public void dispatchStatusRequest(FqCommand.StatusRequest cmd) {
    Date d = cmd.getDate();
    Map<String,Long> m = cmd.getMap();
    System.err.println("Status: " + d);
    for(String key : m.keySet()) {
      System.err.println("    " + key + " : " + m.get(key));
    }
  }
}
