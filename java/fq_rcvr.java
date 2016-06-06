import com.circonus.FqClient;
import com.circonus.FqClientImplDebug;
import com.circonus.FqClientImplNoop;
import com.circonus.FqClientImplInterface;
import com.circonus.FqCommand;
import com.circonus.FqMessage;

public class fq_rcvr {
  private static class FqTest extends FqClientImplDebug {
		private FqClient client;
		private long count = 0;
		private long incr = 0;
		private long s = 0;
		public void setClient(FqClient c) { client = c; }
		public void dispatch(FqMessage m) {
			count++; incr++;
			client.send(m);
		}
		public void dispatchAuth(FqCommand.Auth a) {
			if(a.success()) {
				client.setHeartbeat(500);
				FqCommand.BindRequest breq = new FqCommand.BindRequest(
				  "maryland", "prefix:\"test.prefix.\" sample(1)", false
				);
				client.send(breq);
			}
		}
		public void showRate() {
			long now = System.nanoTime();
			if(s != 0) {
				System.err.println(count + "  [" + 1000000000.0 * (double)incr/((double)now-s) + " m/s]");
				incr = 0;
			}
			s = now;
		}
	}
	public static void main(String args[]) {
    if(args.length != 4) {
      System.err.println(": <host> <port> <user> <pass>");
      System.exit(-1);
    }
		System.err.println(args[0]);
		FqClient client = null;
    FqTest impl = new FqTest();
		try {
		  client = new FqClient(impl);
			client.creds(args[0], new Integer(args[1]), args[2], args[3]);
			client.connect();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}

		while(true) {
			client.send(new FqCommand.StatusRequest());
			try { Thread.sleep(1000); } catch(InterruptedException ignore) { }
		}

		//if(client != null) client.shutdown();
	}
}
