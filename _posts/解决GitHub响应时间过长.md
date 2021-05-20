# 解决GitHub响应时间过长



ip地址可能过一段时间就不一样。

在下列网址查询以下信息：

github网址查询：https://github.com.ipaddress.com/
github域名查询：https://fastly.net.ipaddress.com/github.global.ssl.fastly.net
github静态资源ip：https://github.com.ipaddress.com/assets-cdn.github.com

win + R , 输入：C:\WINDOWS\system32\drivers\etc

按照以下格式将内容写入hosts文件：

```
140.82.114.4 github.com
199.232.69.194 github.global.ssl.fastly.net
185.199.108.153 assets-cdn.github.com
185.199.110.153 assets-cdn.github.com
185.199.111.153 assets-cdn.github.com
```

注意这些值是会变化的，按查询的数据为准。

还有就是可能会遇到hosts文件没有写入权限的情况，可以先把hosts文件拖到桌面，再写入内容，再把文件放回去。