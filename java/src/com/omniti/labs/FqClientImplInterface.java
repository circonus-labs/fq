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

import com.omniti.labs.FqCommand;

public interface FqClientImplInterface {
  public class InUseException extends Exception { }
  public void setClient(FqClient c) throws InUseException;
	public void connectError(Throwable e);
	public void commandError(Throwable e);
  public void dataError(Throwable e);
	public void dispatch(FqMessage m);
  public void dispatch(FqCommand cmd);
  public void dispatchAuth(FqCommand.Auth cmd);
  public void dispatchHeartbeat(FqCommand.Heartbeat cmd);
  public void dispatchHeartbeatRequest(FqCommand.HeartbeatRequest cmd);
  public void dispatchBindRequest(FqCommand.BindRequest cmd);
  public void dispatchUnbindRequest(FqCommand.UnbindRequest cmd);
  public void dispatchStatusRequest(FqCommand.StatusRequest cmd);
}
