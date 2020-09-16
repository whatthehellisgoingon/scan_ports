# scan_ports

## 脚本质量:本脚本已通过[ShellCheck](https://www.shellcheck.net/ "ShellCheck")问题检测分析

## scan_ports.sh脚本背景

扫描端口开关状态方法有很多，如

- [nmap](https://nmap.org/ "nmap")

- ncat/nc

- 各种编程语言提供的网络库

- socat

- bash中的enable-net-redirections选项功能--/dev/tcp/host/port和/dev/udp/host/port伪设备pseudo device(man bash中REDIRECTION部分,见[此链接](https://www.gnu.org/software/bash/manual/bash.html#Redirections "Redirections"))

- telnet

如果在linux下仅使用bash、telnet,自己如何写一个扫描端口开关状态的bash脚本呢？这个就是我写这个脚本的用途。

## scan_ports.sh脚本说明

### 扫描场景

scan_ports.sh脚本支持两种扫描场景,如下:

1. 本地主机扫描:在本机进行端口扫描

2. 远程主机扫描:通过在跳板机登录已经ssh免密的主机后,远程执行端口扫描

### 扫描模式解释

scan_ports.sh脚本支持两种扫描模式,如下:

1. telent模式

2. bash中/dev/tcp/host/port和/dev/udp/host/port伪设备个功能--pseudo device模式

    pseudo device模式比telnet模式速度快.

### 用法说明

```bash
scan_ports.sh [--pd] [--ssh] [--sourcefile /path/to/source/ip/file] [--destfile /path/to/destination/ip/file] [-s source_ip_format] [-d destination_ip_format] [-p port]  [-t timeout_second] [-h]
```

- **--pd**

  开启pseudo device模式，默认是telnet模式

- **--ssh**
  
  开启本地主机扫描模式，默认开启本地主机模式，要与-s参数搭配使用进行远程主机扫描

- **-t 超时时间**

  timeout命令结束的时间,单位为秒,不设置则取脚本中`Default_Telnet_Time_Out_Second`变量默认值

- **-s 源IP地址**
  
  源IP地址是用于从跳板机ssh登录的远程主机IP，要与--ssh参数搭配使用进行远程主机扫描，ssh要免密，不然会被认为ssh连接失败。ip格式支持3种:1是192.168.1.1;2是192.168.1-254;3是192.168.1.1/24(cidr),这3种格式的任意一种格式可以利用逗号区分并组合在一起，例子如:-s 192.168.1.1,192.168.15、-s 192.168.1.1,192.168.1.15-20,192.168.1.0/25。

- **-d 目的IP地址**

  格式和源IP地址一样。

- **--sourcefile 源IP地址所在的文件路径**
  
  如果源IP地址很多而且没有规律，这个场景可以把这些IP放到一个文件中，一行建议只写一种IP格式。

- **--destfile 目的IP地址所在的文件路径**

  要求与--sourcefile参数一样

- **-p 端口**

  端口格式支持2种：1是80；2是1000-1050，这2种格式的任意一种格式可以利用逗号区分并组合在一起,例子如:-p 22,80,443、-p 80,443,1080-1090,9090-9095。

- **-h 显示帮助**

### 使用前的环境准备

- ssh(远程主机扫描)

- bash(版本最好4.0以上)

- telnet(如果使用--pd参数,开启了pseudo device扫描模式,可以不需要)

- timeout(近几年发布linux发行版都自带这个命令,如果没有请使用如下perl写的timeout函数`perl_Timeout`,替换timeout命令所在的位置,并注释脚本中`check_Command_Exsit timeout`这行内容)

```bash
perl_Timeout() {
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

#### 1. 本地主机扫描

- IP直接为参数进行本地主机扫描模式,使用telnet模式,命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5
```

- IP直接为参数进行本地主机扫描模式,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh --pd -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5
```

- IP以文件形式作为参数进行本地扫描模式,使用telnet模式,命令演示(超时时间设置为5秒)如下:

`~/destinatioin_ip.config`文件内容

```bash
cat ~/destinatioin_ip.config
223.5.5.5
104.243.30.84
192.168.122.11-15
192.168.122.12/30
```

```bash
bash ./scan_ports.sh --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5
```

- IP以文件形式作为参数进行本地扫描模式,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh --pd --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5
```

#### 2. 远程主机扫描模式

- IP直接为参数进行远程主机扫描模式,**-s参数中远程主机IP已做好ssh免密**,使用telnet模式,命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh --ssh -s 192.168.122.11,192.168.122.12/31,192.168.122.14-15 -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5
```

- IP直接为参数进行远程主机扫描模式,**-s参数中远程主机IP已做好ssh免密**,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh --ssh --pd -s 192.168.122.11,192.168.122.12/31,192.168.122.14-15 -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5
```

- IP以文件形式作为参数进行远程主机扫描模式,**-s参数中远程主机IP已做好ssh免密**,使用telnet模式,命令演示(超时时间设置为5秒)如下:

`~/source_ip.confg`文件内容

```bash
cat  ~/source_ip.confg
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

```bash
bash ./scan_ports.sh --ssh --sourcefile ~/source_ip.confg --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5
```

- IP以文件形式作为参数进行远程主机扫描模式,**-s参数中远程主机IP已做好ssh免密**,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:

```bash
bash ./scan_ports.sh --ssh --pd --sourcefile ~/source_ip.confg --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5
```
