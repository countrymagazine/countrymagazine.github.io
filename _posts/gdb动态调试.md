# gdb动态调试及解决其中遇到的问题

## 动态调试代码：

```python
from pwn import*
import pwnlib
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
sh = process('./xxx')
#需要中断调试的位置
pwnlib.gdb.attach(proc.pidof(sh)[0],gdbscript="b main")
pause()

```

其中一开始我是这样的：

```python
from pwn import*  
p = process('./xxxx')  
context.terminal=['gnome-terminal','sh',-x]
payload = .....  
gdb.attach(p)  
pause()  
p.sendline(payload)  
p.interactive()  
```

但是报错：`Could not find a terminal binary to use. Set context.terminal to your terminal`

查询发现应该是没有安装gnome。

所以改用tmux。 tmux是一个开源工具，用于在一个终端窗口中运行多个终端会话。

tmux安装：

```
sudo apt-get install tmux
```

安装后这样写代码：

```python
from pwn import*
import pwnlib
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
sh = process('./xxx')
#需要中断调试的位置
pwnlib.gdb.attach(proc.pidof(sh)[0],gdbscript="b main")
pause()
```

之后在运行终端进入tmux界面：

![tmux1](C:\Users\陈泽培\Desktop\学习用图\tmux1.png)

运行脚本，即可进行调试。

![tmux](C:\Users\陈泽培\Desktop\学习用图\tmux.png)