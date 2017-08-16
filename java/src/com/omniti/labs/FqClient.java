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
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.channels.Selector;
import java.nio.channels.spi.AbstractSelector;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.LinkedList;
import java.util.UUID;
import com.omniti.labs.FqClientImplInterface;
import com.omniti.labs.FqCommand;
import com.omniti.labs.FqMessage;

public class FqClient {
  public final static int FQ_PROTO_CMD_MODE = 0xcc50cafe;
  public final static int FQ_PROTO_DATA_MODE = 0xcc50face;
  public final static int FQ_PROTO_PEER_MODE = 0xcc50fade;

  private int mode;
  private String host;
  private SocketAddress hostaddr;
  private int port;
  private String user;
  private String queue;
  private String queue_type;
  private String pass;
  private int q_stall_time;
  private int qmaxlen;
  private final FqMessage endpost = new FqMessage();

  private boolean stop = false;
  private boolean shutting_down = false;
  private boolean data_ready = false;
  private short cmd_hb_ms = 0;
  private short last_cmd_hb_ms = 0;
  private long cmd_hb_last;
  private long cmd_hb_last_sent = 0;
  private FqClientImplInterface impl;
  private AbstractSelector cmd_selector;
  private SocketChannel cmd_socket;
  private ByteBuffer cmd_in_buff;
  private ByteBuffer data_in_buff;
  private AbstractSelector data_selector;
  private SelectionKey data_skey;
  private SocketChannel data_socket;
  private Object keylock = new Object();
  private boolean connected = false;
  private byte client_key[];
  private Thread worker;
  private Thread data_worker;
  private Thread back_worker;
  private Thread sender_worker;
  private final Object sender_worker_lock = new Object();
  private AtomicInteger qlen;
  private ConcurrentLinkedQueue<FqCommand> cmdq;
  private LinkedBlockingQueue<FqMessage> q;
  private LinkedBlockingQueue<FqMessage> backq;
  private FqCommand.Heartbeat reusable_hb;

  private void initialize(FqClientImplInterface _impl, int _mode, int bsize)
    throws FqClientImplInterface.InUseException {
    impl = _impl;
    impl.setClient(this);
    mode = _mode;
    qlen = new AtomicInteger(0);
    cmdq = new ConcurrentLinkedQueue<FqCommand>();
    q = new LinkedBlockingQueue<FqMessage>();
    backq = new LinkedBlockingQueue<FqMessage>();
    reusable_hb = new FqCommand.Heartbeat();
    cmd_in_buff = ByteBuffer.allocate(65536);
    data_in_buff = ByteBuffer.allocate(bsize);
    data_in_buff.mark();
  }
  public FqClient(FqClientImplInterface _impl)
    throws FqClientImplInterface.InUseException {
    initialize(_impl, FQ_PROTO_DATA_MODE, 4194304);
  }
  public FqClient(FqClientImplInterface _impl, int _mode)
    throws FqClientImplInterface.InUseException {
    initialize(_impl, _mode, 4194304);
  }
  public FqClient(FqClientImplInterface _impl, int _mode, int _bsize)
    throws FqClientImplInterface.InUseException {
    initialize(_impl, _mode, _bsize);
  }
  public boolean isPeermode() { return (mode == FQ_PROTO_PEER_MODE); }
  public FqClientImplInterface getImpl() { return impl; }
  public void setHeartbeat(short ms) {
    if(ms != cmd_hb_ms) {
      cmd_hb_ms = ms;
      send(new FqCommand.HeartbeatRequest(cmd_hb_ms));
    }
  }
  public void setHeartbeat(int ms) {
    setHeartbeat((short)ms);
  }
  public void set_backlog(int len, int stall) {
    qmaxlen = len;
    q_stall_time = stall;
  }
  public void send(FqCommand cmd) {
    cmdq.offer(cmd);
  }
  public void send(FqMessage m) {
    q.offer(m);
  }
  public void creds(int _port, String _source, String _pass)
      throws java.net.UnknownHostException {
    creds(null, _port, _source, _pass);
  }
  public void creds(String _host, String _source, String _pass)
      throws java.net.UnknownHostException {
    creds(_host, 0, _source, _pass);
  }
  public void creds(String _host, int _port,
      String _source, String _pass)
      throws java.net.UnknownHostException {
    int cidx;
    if(_host != null) host = _host;
    if(host == null) host = "127.0.0.1";
    if(_port != 0) port = _port % 0xffff;
    if(port == 0) port = 8765;
    user = _source;
    if((cidx = user.indexOf("/")) >= 0) {
      queue = user.substring(cidx + 1);
      user = user.substring(0, cidx);
      if((cidx = queue.indexOf("/")) >= 0) {
        queue_type = queue.substring(cidx + 1);
        queue = queue.substring(0, cidx);
      }
    }

    if(queue == null || queue.length() == 0)
      queue = UUID.randomUUID().toString();
    if(queue_type == null || queue_type.length() == 0)
      queue_type = "mem";
    pass = _pass;
    hostaddr = new InetSocketAddress(host, port);
  }
  private boolean client_do_auth() throws IOException, FqCommandProtocolError {
    FqCommand.PlainAuth auth =
      new FqCommand.PlainAuth(user,pass,queue,queue_type);
    auth.send(this);
    auth.process(this);
    client_key = auth.getKey();
    return (client_key != null);
  }
  public byte[] cmd_read_short_bytearray() throws IOException {
    cmd_in_buff.clear();
    cmd_in_buff.limit(2);
    if(cmd_socket.read(cmd_in_buff) == -1) return null;
    cmd_in_buff.flip();
    Short strlen = cmd_in_buff.getShort();
    cmd_in_buff.clear();
    cmd_in_buff.limit(strlen);
    if(cmd_socket.read(cmd_in_buff) == -1) return null;
    byte a[] = new byte[strlen];
    cmd_in_buff.flip();
    cmd_in_buff.get(a);
    return a;
  }
  public String cmd_read_short_string() throws IOException {
    byte a[] = cmd_read_short_bytearray();
    if(a == null) return null;
    return new String(a, StandardCharsets.UTF_8);
  }
  public ByteBuffer cmd_read(int len) throws IOException {
    if(len > cmd_in_buff.capacity()) {
      ByteBuffer bb = ByteBuffer.allocate(len);
      if(cmd_socket.read(bb) == -1) return null;
      return bb;
    }
    cmd_in_buff.clear();
    cmd_in_buff.limit(len);
    if(cmd_socket.read(cmd_in_buff) == -1) return null;
    return cmd_in_buff;
  }
  public long data_write(ByteBuffer bb) throws IOException {
    return data_socket.write(bb);
  }
  public long data_write(ByteBuffer[] bb) throws IOException {
    return data_socket.write(bb);
  }
  public int cmd_write(ByteBuffer bb) throws IOException {
    return cmd_socket.write(bb);
  }
  private boolean client_data_connect_internal() {
    boolean success = false;
    try {
      data_selector = (AbstractSelector)Selector.open();
      data_socket = data_selector.provider().openSocketChannel();
      data_socket.connect(hostaddr);
      data_socket.socket().setTcpNoDelay(true);
      ByteBuffer bb = ByteBuffer.allocate(4 + 2 + client_key.length);
      bb.order(ByteOrder.BIG_ENDIAN);
      bb.putInt(mode);
      bb.putShort((short)client_key.length);
      bb.put(client_key);
      bb.flip();
      data_write(bb);
      data_socket.configureBlocking(false);
      data_skey = data_socket.register(data_selector, SelectionKey.OP_READ);
    } catch(Exception e) {
      impl.connectError(e);
      return success;
    }
    return success;
  }
  private void reset() {
    try { cmd_socket.close(); } catch (Exception ce) { ce.printStackTrace(); }
    try { data_socket.close(); } catch (Exception ce) { ce.printStackTrace(); }
    data_ready = false;
    cmd_hb_last_sent = 0;
    cmd_hb_last = 0;
  }
  private boolean client_connect_internal() {
    boolean success = false;
    // Force close
    reset();
    try {
      cmd_selector = (AbstractSelector)Selector.open();
      cmd_socket = cmd_selector.provider().openSocketChannel();
      cmd_socket.connect(hostaddr);
      cmd_socket.socket().setTcpNoDelay(true);
      cmd_socket.socket().setSoTimeout(5000);
      setHeartbeat((cmd_hb_ms != 0) ? cmd_hb_ms : (short)10000);
      ByteBuffer bb = ByteBuffer.allocate(4);
      bb.order(ByteOrder.BIG_ENDIAN);
      bb.putInt(FQ_PROTO_CMD_MODE);
      bb.flip();
      cmd_write(bb);
      success = client_do_auth();
    } catch(Exception e) {
      impl.connectError(e);
      return success;
    }
    return success;
  }
  public void connect() {
    if(connected) return;
    worker = new Thread() {
        public void run() { worker(); }
     };
    worker.setName("Fq-cmd(" + host + ")");
    worker.start();
    data_worker = new Thread() {
        public void run() { data_worker(); }
     };
    data_worker.setName("Fq-data-in(" + host + ")");
    data_worker.start();
    back_worker = new Thread() {
        public void run() { back_worker(); }
     };
    back_worker.setName("Fq-back(" + host + ")");
    back_worker.start();
  }
  public void recvHeartbeat() {
    cmd_hb_last = System.nanoTime();
  }
  private void sendHeartbeat() throws IOException, FqHeartbeatException {
    long t = System.nanoTime();
    if((t - cmd_hb_last_sent) > ((long)cmd_hb_ms * 1000000)) {
      reusable_hb.send(this);
      cmd_hb_last_sent = t;
    }
    if(cmd_hb_ms != last_cmd_hb_ms) {
      cmd_socket.socket().setSoTimeout(cmd_hb_ms * 2);
      last_cmd_hb_ms = cmd_hb_ms;
    }
    long hb_ns = (long)cmd_hb_ms * (long)3 * (long)1000000;
    if(cmd_hb_last != 0 && hb_ns != 0 &
      cmd_hb_last < (t - hb_ns)) {
      throw new FqHeartbeatException();
    }
  }
  public int data_backlog() { return qlen.get(); }
  private void worker() {
    int backoff = 0;
    while(!stop) {
      LinkedList<FqCommand> responses = new LinkedList<FqCommand>();
      try {
        if(client_connect_internal()) {
          data_ready = true;
          backoff = 0;
        }
        while(!stop && data_ready) {
          FqCommand entry;
          while(null != (entry = cmdq.poll())) {
            entry.send(this);
            if(entry.hasInBandResponse()) {
              responses.addLast(entry);
            }
          }

          sendHeartbeat();

          entry = responses.pollFirst();
          if(entry == null) entry = reusable_hb;
          entry.process(this);
        }
      } catch(Exception e) {
        impl.commandError(e);
      }
      try {
        Thread.sleep(backoff / 1000, (backoff % 1000) * 1000);
      } catch(InterruptedException ignore) {}
      backoff += 10000;
    }
  }
  private void data_worker_sender() {
    FqMessage m;
    while(!stop && cmd_socket.socket().isConnected()) {
      m = null;
      try { m = q.take(); } catch(InterruptedException ignore) { }
      if(m == endpost) break;
      if(m == null) continue;
      try {
        while(!m.send(this) && !stop && cmd_socket.socket().isConnected()) {
          synchronized(keylock) {
            data_skey.interestOps(SelectionKey.OP_READ|SelectionKey.OP_WRITE);
            try { keylock.wait(); } catch(InterruptedException ignore) { }
          }
        }
      } catch(IOException e) {
        impl.dataError(e);
        return;
      } catch(FqDataProtocolError e) {
        impl.dataError(e);
        return;
      }
    }
  }
  private void waitForData(long ms) throws IOException {
    data_selector.select(ms);
    if(data_skey.isWritable()) {
      synchronized(keylock) {
        data_skey.interestOps(SelectionKey.OP_READ);
        keylock.notify();
      }
    }
  }
  public int blockingRead(byte dst[], int offset, int len) throws IOException {
    ByteBuffer rest = ByteBuffer.wrap(dst, offset, len);
    int nread = 0;
    // A quick non-blocking attempt
    if((nread = data_socket.read(rest)) == len) {
      return len; // done.
    }
    if (nread < 0) throw new IOException();

    while(rest.position() < (offset+len)) {
      int readlen;
      waitForData(1000);
      while((readlen = data_socket.read(rest)) > 0) {
        nread += readlen;
      }
      if(readlen < 0) throw new IOException();
    }
    return nread;
  }
  public ByteBuffer fill_data_buffer(boolean force) throws IOException {
    if(force || data_in_buff.position() == 0) {
      waitForData(1000);
      int rsize = data_socket.read(data_in_buff);
      if(rsize < 0) throw new IOException("bad read");
    }
    return data_in_buff;
  }

  private void data_worker_receiver() {
    while(!stop && cmd_socket.socket().isConnected()) {
      FqMessage m;
      m = new FqMessage();
      try { while(!stop && !m.read(this)) fill_data_buffer(true); }
      catch (IOException e) { impl.dataError(e); reset(); return; }
      catch (FqDataProtocolError e) { impl.dataError(e); reset(); return; }
      if(m.isComplete()) {
        do {
          try {
            backq.put(m);
            m = null;
          }
          catch(InterruptedException ignore) { }
        } while(m != null);
      }
    }
  }
  private void data_worker() {
    int backoff = 0;
    Error boom = null;
    while(!stop) {
      if(data_ready) {
        try {
          if(client_data_connect_internal()) {
            backoff = 0;
          }

          sender_worker = new Thread() {
            public void run() { data_worker_sender(); }
           };
          sender_worker.setName("Fq-data-out(" + host + ")");
          sender_worker.start();
          try {
            data_worker_receiver();
          } catch (Error e) {
            impl.dataError(e);
            q.offer(endpost);
            reset();
            boom = e;
          }
          try { sender_worker.interrupt(); } catch (Exception ignore) { }
          synchronized(sender_worker_lock) {
            sender_worker.join();
          }
  
        } catch(Exception e) {
          impl.dataError(e);
        }
      }
      if(backoff < 1000000) backoff += 10000;
      try {
        Thread.sleep(backoff / 1000, (backoff % 1000) * 1000);
      } catch(InterruptedException ignore) {}
    }
    shutting_down = true;
    backq.offer(endpost);
    if(boom != null) throw(boom);
  }
  private void back_worker() {
    while(!shutting_down) {
      try {
        FqMessage m = backq.take();
        if(m == endpost) break;
        impl.dispatch(m);
      } catch(InterruptedException ignore) { }
    }
  }
  public void shutdown() {
    stop = true;
    q.offer(endpost);
    try {
      synchronized(sender_worker_lock) {
        sender_worker.join();
      }
      data_worker.join();
      worker.join();
    } catch(InterruptedException ignore) { }
  }
}
