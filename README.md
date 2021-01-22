# py_safe_coding
python的各类漏洞示范及对应提供修复代码

## 涵盖漏洞有：

- [x] xss跨站脚本攻击
- [x] sql注入漏洞
- [x] 目录遍历/目录穿越/任意文件读取/任意文件下载
- [x] ssrf服务端请求伪造
- [x] 命令执行/注入
- [x] 文件上传
- [x] csrf跨域请求伪造
- [x] xxe-xml注入
- [x] 反序列化漏洞

## 调用测试：
安装依赖pip3 install -r requirements.txt
执行manage.py，直接调用接口和参数直接测试。
如：命令执行测试http://0.0.0.0:8888/api/cmdexec/?filename=test.txt;whoami&type=infected_1

## 贡献
1. 如果存在使用上的问题，欢迎提issue.