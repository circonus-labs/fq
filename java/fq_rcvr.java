import com.omniti.labs.FqClient;
import com.omniti.labs.FqClientImplDebug;
import com.omniti.labs.FqClientImplNoop;
import com.omniti.labs.FqClientImplInterface;
import com.omniti.labs.FqCommand;
import com.omniti.labs.FqMessage;

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
    int seconds = 30;
		System.err.println(args[0]);
    FqTest impl = new FqTest();
		FqClient client = new FqClient(impl);
		impl.setClient(client);
		FqCommand.BindRequest breq = null;
		try {
			client.creds(args[0], new Integer(args[1]), args[2], args[3]);
			client.connect();
			client.setHeartbeat(500);
			breq = new FqCommand.BindRequest(
			  "maryland", "prefix:\"test.prefix.\" sample(1)", false
			);
			client.send(breq);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}

    FqCommand.UnbindRequest ubreq = null;
		while(seconds-- > 0) {
			impl.showRate();
			try { Thread.sleep(1000); } catch(InterruptedException e) {}
			if(false && breq != null) {
				if(breq.getBinding() != null) {
					ubreq = new FqCommand.UnbindRequest(breq);
					client.send(ubreq);
					breq = null;
				}
			}
			else if(ubreq != null) {
				if(ubreq.getSuccess()) {
					breq = new FqCommand.BindRequest(
					  "maryland", "prefix:\"test.prefix.\" sample(1)", false
					);
					client.send(breq);
					ubreq = null;
				}
			}
		}
		client.shutdown();
	}
}
