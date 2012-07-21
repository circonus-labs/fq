fq*:::message-receive{
  msg = xlate <fq_msg_t> ((fq_dtrace_msg_t *)arg2);
  printf("sender: %s\n", msg.sender);
  printf("exchange: %s\n", msg.exchange);
  printf("route: %s\n", msg.route);
  printf("message len: %d\n", msg.payload_len);
  printf("message: %.*s\n", msg.payload_len, msg.payload);
 
  c = xlate <fq_remote_anon_client_t> ((fq_dtrace_remote_anon_client_t *)arg0);
  printf("client: %s\n", c.pretty);
}

fq*:::queue-drop{
  q = xlate <fq_queue_t> ((fq_dtrace_queue_t *)arg0);
  printf("dropped message on queue %s\n", q.name);
}

fq*:::queue-block{
  q = xlate <fq_queue_t> ((fq_dtrace_queue_t *)arg0);
  printf("blocking queue %s\n", q.name);
}
