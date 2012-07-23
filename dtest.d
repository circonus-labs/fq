fq*:::message-receive{
  printf("sender: %s\n", args[2]->sender);
  printf("exchange: %s\n", args[2]->exchange);
  printf("route: %s\n", args[2]->route);
  printf("message len: %d\n", args[2]->payload_len);
  printf("message: %.*s\n", args[2]->payload_len, args[2]->payload);

  printf("client: %s\n", args[0]->pretty); 
  printf("client: %s\n", args[1]->pretty); 
}

fq*:::queue-drop{
  q = ((fq_queue_t *)arg0);
  printf("dropped message on queue %s\n", q->name);
}

fq*:::queue-block{
  printf("blocking queue %s\n", ((fq_queue_t *)arg0)->name);
}
