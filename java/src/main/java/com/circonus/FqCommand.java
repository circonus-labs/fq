/*
 * Copyright (c) 2016 Circonus, Inc.
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

package com.circonus;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import com.circonus.FqClient;

public abstract class FqCommand {
  public final short FQ_PROTO_ERROR = (short)0xeeee;
  public final short FQ_PROTO_HB = (short)0xbea7;
  public final short FQ_PROTO_AUTH_CMD = (short)0xaaaa;
  public final short FQ_PROTO_AUTH_PLAIN = (short)0;
  public final short FQ_PROTO_AUTH_RESP = (short)0xaa00;
  public final short FQ_PROTO_HBREQ = (short)0x4848;
  public final short FQ_PROTO_BIND = (short)0xb171;
  public final short FQ_PROTO_BINDREQ = (short)0xb170;
  public final short FQ_PROTO_UNBIND = (short)0x171b;
  public final short FQ_PROTO_UNBINDREQ = (short)0x071b;
  public final short FQ_PROTO_STATUS = (short)0x57a7;
  public final short FQ_PROTO_STATUSREQ = (short)0xc7a7;

  protected ByteBuffer bb;
  private boolean composed = false;
  public abstract short cmd();
  public short response_cmd() { return cmd(); }
  public void compose() { }
  public void send(FqClient c) throws IOException {
    if(composed) {
      bb.position(0);
    } else {
      bb.putShort(cmd());
      compose();
      bb.flip();
      composed = true;
    }
    int rv = c.cmd_write(bb);
  }
  public abstract boolean hasInBandResponse();
  private static Heartbeat hb = new Heartbeat();

  public Short getShortCmd(FqClient c)
      throws IOException, FqCommandProtocolError {
    Short cmd;
    do {
      ByteBuffer bb = c.cmd_read(2);
      if(bb == null) return null;
      bb.flip();
      cmd = bb.getShort();
      if(cmd == FQ_PROTO_HB) { c.recvHeartbeat(); }
      if(cmd == FQ_PROTO_ERROR) {
        throw new FqCommandProtocolError(c.cmd_read_short_string());
      }
    } while(cmd() != FQ_PROTO_HB && cmd == FQ_PROTO_HB);
    return cmd;
  }
  public void process(FqClient c) throws IOException, FqCommandProtocolError {
    Short cmd = getShortCmd(c);
    // the hearbeat happens magically in getShortCmd
    if(cmd == null || cmd != response_cmd()) {
      throw new FqCommandProtocolError(response_cmd(), cmd);
    }
  }

  protected void alloc(int size) {
    bb = ByteBuffer.allocate(size);
    bb.order(ByteOrder.BIG_ENDIAN);
  }
  public FqCommand(int size) {
    alloc(size + 2);
  }
  public FqCommand() {
  }

  public static class Heartbeat extends FqCommand {
    public Heartbeat() { super(0); }
    public boolean hasInBandResponse() { return false; }
    public short cmd() { return FQ_PROTO_HB; }
  }
  public static class HeartbeatRequest extends FqCommand {
    short ms;
    public HeartbeatRequest(int _ms) {
      super(2);
      ms = (short)(_ms & 0xffff);
    }
    public boolean hasInBandResponse() { return false; }
    public short cmd() { return FQ_PROTO_HBREQ; }
    public void compose() { bb.putShort(ms); }
  }
  public static abstract class Auth extends FqCommand {
    protected byte[] key = null;
    public boolean success() { return (key != null); }
    public byte[] getKey() { return key; }
  }  
  public static class PlainAuth extends Auth {
    private byte b_user[];
    private byte b_pass[];
    private byte b_queue[];
    private byte b_queue_type[];
  
    public PlainAuth(String user, String pass,
      String queue, String queue_type) {
      b_user = user.getBytes();
      b_queue = queue.getBytes();
      b_queue_type = queue_type.getBytes();
      b_pass = pass.getBytes();
      int extra_space = 
        2 + /* plain */
        2 + b_user.length + /* user */
        2 + b_queue.length + 1 + b_queue_type.length + /* queue */
        2 + b_pass.length;
      alloc(2+extra_space);
    }
    public short cmd() { return FQ_PROTO_AUTH_CMD; }
    public boolean hasInBandResponse() { return true; }
    public void compose() {
      bb.putShort(FQ_PROTO_AUTH_PLAIN);
      bb.putShort((short)b_user.length);
      bb.put(b_user);
      bb.putShort((short)(b_queue.length + 1 + b_queue_type.length));
      bb.put(b_queue);
      bb.put((byte) 0);
      bb.put(b_queue_type);
      bb.putShort((short)b_pass.length);
      bb.put(b_pass);
    }
    public void process(FqClient c) throws IOException, FqCommandProtocolError {
      Short cmd, len;
      bb = c.cmd_read(2);
      if(bb == null) return;
      bb.flip();
      cmd = bb.getShort();
      switch(cmd) {
        case FQ_PROTO_AUTH_RESP:
          key = c.cmd_read_short_bytearray();
          if(key == null || key.length > 127)
            throw new FqCommandProtocolError("bad key");
          break;
        case FQ_PROTO_ERROR:
          String error = c.cmd_read_short_string();
          if(error != null) throw new FqCommandProtocolError(error);
          /* fall through */
        default:
          throw new FqCommandProtocolError(cmd);
      }
      c.getImpl().dispatchAuth(this);
    }
  }
  public static class BindRequest extends FqCommand {
    public static final short FQ_BIND_PEER = 0x0001;
    public static final short FQ_BIND_PERM = 0x0110;
    public static final short FQ_BIND_TRANS = 0x0100;
    private Integer binding;
    private byte exchange[];
    private byte program[];
    private short flags;
    
    public BindRequest(byte _exchange[], String _program, short _flags) {
      program = _program.getBytes();
      exchange = _exchange;
      flags = _flags;
      int extra_space = 
        2 + /* flags */
        2 + exchange.length + /* user */
        2 + program.length;
      alloc(2+extra_space);
    }
    public BindRequest(byte _exchange[], String _program, boolean _peermode) {
      this(_exchange, _program, _peermode ? FQ_BIND_PEER : 0);
    }
    public BindRequest(String exchange, String p, boolean m) {
      this(exchange.getBytes(), p, m);
    }
    public short cmd() { return FQ_PROTO_BINDREQ; }
    public short response_cmd() { return FQ_PROTO_BIND; }
    public boolean hasInBandResponse() { return true; }
    public void compose() {
      bb.putShort(flags);
      bb.putShort((short)exchange.length);
      bb.put(exchange);
      bb.putShort((short)program.length);
      bb.put(program);
    }
    public void process(FqClient c) throws IOException, FqCommandProtocolError {
      super.process(c);
      Integer cmd;
      bb = c.cmd_read(4);
      if(bb == null) return;
      bb.flip();
      binding = bb.getInt();
      c.getImpl().dispatchBindRequest(this);
    }
    public Integer getBinding() { return binding; }
    public byte[] getExchange() { return exchange; }
  }
  public static class UnbindRequest extends FqCommand {
    private BindRequest bind;
    private Integer success;
    
    public UnbindRequest(BindRequest b) {
      bind = b;
      int extra_space = 
        2 + /* peermode */
        4 + /* route_id */
        2 + bind.getExchange().length;
      alloc(2+extra_space);
    }
    public short cmd() { return FQ_PROTO_UNBINDREQ; }
    public short response_cmd() { return FQ_PROTO_UNBIND; }
    public boolean hasInBandResponse() { return true; }
    public void compose() {
      bb.putInt(bind.getBinding());
      bb.putShort((short)bind.getExchange().length);
      bb.put(bind.getExchange());
    }
    public void process(FqClient c) throws IOException, FqCommandProtocolError {
      super.process(c);
      Integer cmd;
      bb = c.cmd_read(4);
      if(bb == null) return;
      bb.flip();
      success = bb.getInt();
      c.getImpl().dispatchUnbindRequest(this);
    }
    public Integer getBinding() { return bind.getBinding(); }
    public boolean getSuccess() {
      return (success != null && success == bind.getBinding());
    }
  }

  public static class StatusRequest extends FqCommand {
    protected Date last_update;
    protected HashMap<String,Long> status = new HashMap<String,Long>();
    public StatusRequest() { super(0); }
    public short cmd() { return FQ_PROTO_STATUSREQ; }
    public short response_cmd() { return FQ_PROTO_STATUS; }
    public boolean hasInBandResponse() { return true; }
    public void process(FqClient c) throws IOException, FqCommandProtocolError {
      super.process(c);
      last_update = new Date();
      while(true) {
        String key = c.cmd_read_short_string();
        if(key.length() == 0) break;
        Integer ivalue;
        bb = c.cmd_read(4);
        if(bb == null) throw new FqCommandProtocolError("status read failure");
        bb.flip();
        ivalue = bb.getInt();
        Long value = ivalue & (long)0xffffffff;
        status.put(key,value);
      }
      c.getImpl().dispatchStatusRequest(this);
    }
    public Date getDate() { return last_update; }
    public Map<String,Long> getMap() { return status; }
  }
}
