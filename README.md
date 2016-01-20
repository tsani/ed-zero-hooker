Ed Zero Hooker
==============

A text hooker for the game Zero no Kiseki.

Features:

* Can hook into a running game process.
* Copies text that is about to appear on-screen into the clipboard.

Tested personally on Windows XP, but I've heard it also works on Windows 8.

Due to address space layout randomization, the code location that is hooked
might vary. To account for that, the hooker takes the address to insert the
hook at _in decimal_ as a command-line argument.

For a detailed explaination of how this was built, see the blog post
[here](http://jerrington.me/posts/2015-12-31-windows-debugging-for-fun-and-profit.html).

The blog post also more or less contains instructions for determining what
address needs to be hooked on your machine.
