# ChangeLog

### v0.10.8

 * Fix querystring parsing crash when parameters are not k=v form.
 * Resume on-disk queues at the right checkpoint location.

### v0.10.7

 * Fix bug in route binding prefix matching causing misdirected messages
   (clients could get more than they asked for).
 * Fix bug on some Linux systems regarding exposed symbols.

### v0.10.6

 * Fix crashing issue enqueueing messages due to unsafe use of spsc fifos.
 * Add dynamic loading of routing program extensions.
 * Move the "sample" function to a dynamic extension for example purposes.
