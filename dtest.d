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
fq*:::message-receive{
  printf("sender: %s\n", args[2]->sender);
  printf("exchange: %s\n", args[2]->exchange);
  printf("route: %s\n", args[2]->route);
  printf("message len: %d\n", args[2]->payload_len);
  printf("message: %.*s\n", args[2]->payload_len, args[2]->payload);

  printf("client: %s\n", args[0]->pretty); 
  printf("client: %s\n", args[1]->pretty); 

  printf("latency: %d\n", args[2]->latency);
}

fq*:::queue-drop{
  q = ((fq_queue_t *)arg0);
  printf("dropped message on queue %s\n", q->name);
}

fq*:::queue-block{
  printf("blocking queue %s\n", ((fq_queue_t *)arg0)->name);
}
