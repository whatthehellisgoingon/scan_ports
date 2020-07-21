# scan_ports

## scan_ports.sh脚本背景说明

大家都知道扫描端口的方法有很多，如

- nmap
- ncat/nc
- 各种编程语言提供的网络库
- socat
- bash中/dev/tcp/host/port和/dev/udp/host/port重定向文件(man bash中REDIRECTION部分)
- telnet

如果在linux下仅使用bash、telnet,自己如何造一个端口扫描脚本呢？

这个就是我写这个脚本的用途。

## scan_ports.sh脚本使用说明

### 用法说明

scan_ports.sh脚本支持两种模式

1.本地主机扫描模式:就是在本机telnet目的IP的端口的模式

2.远程主机扫描模式:就是通过跳板机ssh登录已经免密的主机(这里指源IP)后执行telnet目的IP端口模式

用法:

```bash
scan_ports.sh [-l] [-t timeout_second] [--sourcefile /path/to/source/ip/file] [--destfile /path/to/destination/ip/file] [-s source_ip_format] [-d destination_ip_format] [-p port] [-h]
```

- **-l** 开启本地主机扫描模式 当开启本地主机模式，**注意：-s、--sourcefile参数里面源IP将回失去作用！**

- **-t 设置telnet超时而被timeout命令结束的时间** 不设置则取脚本中`Default_Telnet_Time_Out_Second`变量默认值

- **-s 源IP地址** 要用于从跳板机ssh登录的远程主机，ssh要免密，不然还是使用本地主机模式。ip格式支持3种:1是192.168.1.1;2是192.168.1-254;3是192.168.1.1/24(cidr),这3种格式的任意一种格式可以利用逗号区分并组合在一起,例子如:-s 192.168.1.1,192.168.15、-s 192.168.1.1,192.168.1.15-20,192.168.1.0/25。

- **-d 目的IP地址** 格式和源IP地址一样。

- **--sourcefile 源IP地址所在的文件路径** 如果源IP地址很多而且没有规律，这个场景可以把这些IP放到一个文件中，一行建议只写一种IP格式。

- **--destfile 目的IP地址所在的文件路径** 要求与--sourcefile参数一样

- **-p 端口** 端口格式支持2种：1是80；2是1000-1050，这2种格式的任意一种格式可以利用逗号区分并组合在一起,例子如:-p 22,80,443、-p 80,443,1080-1090,9090-9095。

- **-h 显示帮助**

### 使用前的环境准备

- ssh(主要用于登录)
- bash(版本最好4.0以上)
- telnet
- timeout(很多linux发行版都自带这个命令,如果没有请使用如下per写的timeout函数`per_Timeout`,替换timeout命令所在的位置,并注释脚本中`check_Command_Exsit timeout`这行内容)

```bash
per_Timeout() {
  perl -e '
    eval {
      $SIG{ALRM} = sub { die };
      alarm shift;
      system(@ARGV);
    };
    if ($@) { exit 1 }
  ' "$@";
}
```

### 演示例子

#### 1.本地扫描模式

- IP直接为参数的本地扫描模式,命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh -l -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5
```

- IP以文件参数的本地扫描模式

`~/destinatioin_ip.config`文件内容

```bash
cat ~/destinatioin_ip.config
223.5.5.5
104.243.30.84
192.168.122.11-15
192.168.122.12/30
```

命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh -l --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5
```

#### 2.远程主机扫描模式

- IP直接为参数的远程主机扫描模式,**远程主机已做好免密**。命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh -s 192.168.122.11,192.168.122.12/31,192.168.122.14-15 -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5
```

- IP以文件参数的远程主机扫描模式

`~/source_ip.confg`文件内容

```bash
cat > ~/source_ip.confg
192.168.122.11
192.168.122.12/31
192.168.122.14-15
```

`~/destinatioin_ip.config`文件内容

```bash
cat ~/destinatioin_ip.config
223.5.5.5
104.243.30.84
192.168.122.11-15
```

命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh --sourcefile ~/source_ip.confg --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5
```
