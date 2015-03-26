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

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.UUID;
import com.omniti.labs.FqDataProtocolError;

public class FqMessage {
  public class MsgId {
    protected byte d[];
    public MsgId(byte v[]) {
      d = new byte[16];
      System.arraycopy(v,0,d,0,16);
    }
  }

  private boolean _complete = false;

  private int nhops = -1;
  private InetAddress hops[];
  private int route_len = -1;
  private byte route[];
  private int sender_len = -1;
  private byte sender[];
  private int exchange_len = -1;
  private byte exchange[];
  private MsgId sender_msgid;
  private int payload_len = -1;
  private byte payload[];

  private ByteBuffer[] iovec;

  public void setRoute(byte[] _r) { route = _r; route_len = _r.length; }
  public void setSender(byte[] _r) { sender = _r; sender_len = _r.length; }
  public void setExchange(byte[] _r) { exchange = _r; exchange_len = _r.length; }
  public void setMsgId() {
    UUID uuid = UUID.randomUUID();
    ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
    bb.putLong(uuid.getMostSignificantBits());
    bb.putLong(uuid.getLeastSignificantBits());
    sender_msgid = new MsgId(bb.array());
  }
  public void setPayload(byte[] _r) { payload = _r; payload_len = _r.length; }

  public String getRoute() { return new String(route); }
  public String getExchange() { return new String(exchange); }
  public String getSender() { return new String(sender); }
  public MsgId getMsgId() { return sender_msgid; }
  public byte[] getPayload() { return payload; }
  public InetAddress[] getPath() { return hops; }

  public boolean isComplete(boolean peermode) {
    if(peermode) {
      if(nhops < 0 || hops == null || sender_len < 0 || sender == null)
        return false;
    }
    if(route_len <= 0 || route == null ||
      exchange_len <= 0 || exchange == null ||
      payload_len < 0 || payload == null || sender_msgid == null)
      return false;
    return true;
  }
  public boolean isComplete() { return _complete; }
  public boolean read(FqClient c) throws IOException, FqDataProtocolError {
    boolean success;
    int limit, position;
    if(isComplete()) return true;
    ByteBuffer bb = c.fill_data_buffer(false);
    // Save fill location
    position = bb.position();
    limit = bb.limit();
    // Set read location
    bb.reset();
    bb.limit(position);

    success = readInternal(c, bb);

    if(!success) {
      // compact while reading
      bb.compact();
      // after compaction, position is a fill position
      position = bb.position();
      // mark at zero (as we've compacted)
      bb.position(0);
      bb.mark();
      // restore the fill position
      bb.position(position);
    } else {
      // restore fill position
      bb.limit(limit);
      bb.position(position);
    }
    return success;
  }
  private boolean readInternal(FqClient c, ByteBuffer bb)
    throws IOException, FqDataProtocolError {
    if(isComplete()) return true;
    if(exchange_len == -1) {
      if(bb.remaining() < 1) return false;
      byte len = bb.get();
      exchange_len = len;
      bb.mark();
      if(exchange_len <= 0 || exchange_len > 127)
        throw new FqDataProtocolError("invalid exchange_len: " + exchange_len);
    }
    if(exchange == null) {
      if(bb.remaining() < exchange_len) return false;
      exchange = new byte[exchange_len];
      bb.get(exchange);
      bb.mark();
    }
    if(route_len == -1) {
      if(bb.remaining() < 1) return false;
      route_len = (int)bb.get();
      bb.mark();
      if(route_len < 0 || route_len > 127)
        throw new FqDataProtocolError("invalid route_len: " + route_len);
    }
    if(route == null) {
      if(bb.remaining() < route_len) return false;
      route = new byte[route_len];
      bb.get(route);
      bb.mark();
    }
    if(sender_msgid == null) {
      if(bb.remaining() < 16) return false;
      byte[] m = new byte[16];
      bb.get(m);
      bb.mark();
      sender_msgid = new MsgId(m);
    }
    if(sender_len == -1) {
      if(bb.remaining() < 1) return false;
      sender_len = (int)bb.get();
      bb.mark();
      if(sender_len < 0 || sender_len > 127)
        throw new FqDataProtocolError("invalid sender_len: " + sender_len);
    }
    if(sender == null) {
      if(bb.remaining() < sender_len) return false;
      sender = new byte[sender_len];
      bb.get(sender);
      bb.mark();
    }
    if(nhops == -1) {
      if(bb.remaining() < 1) return false;
      nhops = (int)bb.get();
      if(nhops < 0 || nhops > 32)
        throw new FqDataProtocolError("invalid nhops: " + nhops);
      bb.mark();
    }
    if(hops == null) {
      if(bb.remaining() < nhops * 4) return false;
      hops = new InetAddress[nhops];
      byte ip[] = new byte[4];
      for(int i=0;i<nhops;i++) {
        bb.get(ip);
        hops[i] = InetAddress.getByAddress(ip);
      }
      bb.mark();
    }
    if(payload_len == -1) {
      if(bb.remaining() < 4) return false;
      payload_len = bb.getInt();
      bb.mark();
    }
    if(payload == null && payload_len > 0) {
      payload = new byte[payload_len];
      if(bb.remaining() >= payload_len) {
        bb.get(payload);
      } else {
        int havenow = bb.remaining();
        bb.get(payload, 0, havenow);
        int nread = c.blockingRead(payload, havenow, payload_len - havenow);
        if((nread+havenow) != payload_len)
          throw new FqDataProtocolError("payload read failure: " + nread + "+" + havenow + " != " + payload_len);
      }
      bb.mark();
    }
    _complete = true;
    return true;
  }

  public boolean send(FqClient c) throws IOException, FqDataProtocolError {
    if(!isComplete(c.isPeermode())) throw new FqDataProtocolError("incomplete message");
    if(iovec == null) {
      int i = 0;
      iovec = new ByteBuffer[c.isPeermode() ? 11 : 7];
      iovec[i  ] = ByteBuffer.allocate(1).put((byte)exchange_len);
      iovec[i++].flip();
      iovec[i++] = ByteBuffer.wrap(exchange);
      iovec[i  ] = ByteBuffer.allocate(1).put((byte)route_len);
      iovec[i++].flip();
      iovec[i++] = ByteBuffer.wrap(route);
      iovec[i++] = ByteBuffer.wrap(sender_msgid.d);
      if(c.isPeermode()) {
        iovec[i  ] = ByteBuffer.allocate(1).put((byte)sender_len);
        iovec[i++].flip();
        iovec[i++] = ByteBuffer.wrap(sender);
        iovec[i  ] = ByteBuffer.allocate(1).put((byte)nhops);
        iovec[i++].flip();
        iovec[i  ] = ByteBuffer.allocate(nhops * 4);
        for(int j=0; j<nhops; j++)
          iovec[i].put(hops[j].getAddress());
        iovec[i++].flip();
      }
      iovec[i  ] = ByteBuffer.allocate(4).putInt(payload_len);
      iovec[i++].flip();
      iovec[i++] = ByteBuffer.wrap(payload);
    }
    if(c.data_write(iovec) < 0) throw new IOException();
    if(iovec[iovec.length-2].position() == 4 &&
      iovec[iovec.length-1].position() == payload_len) {
      iovec = null;
      return true;
    }
    return false;
  }
}
