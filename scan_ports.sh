#!/usr/bin/env bash


# >>>>>>>>>>>>>>>>>>>>>>>>全局变量>>>>>>>>>>>>>>>>>>>>>>>>

BaseDir=$(cd "$(dirname "$0")" && pwd || exit) #脚本所在目录

Result_Dir=${BaseDir}/result #扫描结果的总目录

Local_Pd_Scan_Result=${Result_Dir}/local_pd_scan_result_$(date +%Y%m%d%H%M%S) #在本地主机pseudo device扫描模式的结果目录

Local_Pd_Scan_Connected_Log=${Local_Pd_Scan_Result}/local_pd_scan_connected.log #记录在本地主机pseudo device扫描模式端口为Connected(open)状态的结果日志

Local_Pd_Scan_Close_Log=${Local_Pd_Scan_Result}/local_pd_scan_close.log #记录在本地主机pseudo device扫描模式的端口为Close状态的结果日志

Ssh_Pd_Scan_Result=${Result_Dir}/ssh_pd_scan_result_$(date +%Y%m%d%H%M%S) #ssh到远程主机pseudo device扫描模式的结果目录

Ssh_Pd_Scan_Connected_Log=${Ssh_Pd_Scan_Result}/ssh_pd_scan_connected.log #记录ssh到远程主机pseudo device扫描模式端口为Connected(open)状态的结果日志

Ssh_Pd__Scan_Close_Log=${Ssh_Pd_Scan_Result}/ssh_pd_scan_close.log #记录ssh到远程主机pseudo device扫描模式端口为Close状态的结果日志

Local_Telnet_Scan_Result=${Result_Dir}/local_telnet_scan_result_$(date +%Y%m%d%H%M%S) #在本地主机telnet扫描模式的结果目录

Local_Telnet_Connected_Log=${Local_Telnet_Scan_Result}/local_telnet_scan_connected.log #记录本地主机telnet扫描模式端口为Connected(open)状态的结果日志

Local_Telnet_Refuse_Log=${Local_Telnet_Scan_Result}/local_telnet_scan_refuse.log #记录本地主机telnet扫描模式端口为Refuse状态的结果日志

Local_Telnet_Close_Log=${Local_Telnet_Scan_Result}/local_telnet_scan_close.log #记录本地主机telnet扫描模式端口为Close状态的结果日志

Ssh_Telnet_Scan_Result=${Result_Dir}/ssh_telnet_scan_result_$(date +%Y%m%d%H%M%S) #ssh到远程主机telnet扫描模式的结果目录

Ssh_Telnet_Connected_Log=${Ssh_Telnet_Scan_Result}/ssh_telnet_scan_connected.log #记录ssh到远程主机telnet扫描模式端口为Connected(open)状态的结果日志

Ssh_Telnet_Refuse_Log=${Ssh_Telnet_Scan_Result}/ssh_telnet_scan_refuse.log #记录ssh到远程主机telnet扫描模式端口为Connected(open)状态的结果日志

Ssh_Telnet_Close_Log=${Ssh_Telnet_Scan_Result}/ssh_telnet_scan_close.log #记录ssh到远程主机telnet扫描模式端口为Connected(open)状态的结果日志

Default_Telnet_Time_Out_Second=3 #telnet超时而被timeout结束的默认时间

Telnet_Time_OUT_Second="" #初始化Telnet_Time_OUT_Second变量

Ssh_Scan_Mode='FALSE' #本地主机扫描模式开关,默认是关闭的,脚本加-l参数可以开启本地主机扫描模式

Pseudo_Scan_Engine='FALSE' #在bash下伪设备(pseudo device)--/dev/tcp/host/port引擎扫描模式,默认是关闭的,脚本加--pd参数可以开启伪设备扫描引擎

All_Source_Ip=() #源IP地址数组

All_Destination_Ip=() #目的IP地址数组

All_Ports=() #所扫描端口的数组

RED='\033[0;31m' #输出红颜色

GREEN='\033[0;32m' #输出绿颜色

YELLOW='\033[0;33m' #输出黄颜色

BLUE='\033[0;34m' #输出蓝颜色

NORMAL='\033[0m' #输出恢复

Ssh_Count=0 #ssh到远程主机扫描模式总扫描次数

Ssh_Connected_Count=0 #ssh到远程主机telnet扫描模式结果为Connected的次数

Ssh_Refused_Count=0 #ssh到远程主机telnet扫描模式结果为Refused的次数,ssh到远程主机pseudo device扫描模式没有这种扫描结果

Ssh_Close_Count=0 #ssh到远程主机telnet扫描模式结果为Close的次数

Sucess_Ssh_Server=0 #ssh到远程主机成功次数

Failed_Ssh_Server=0 #ssh到远程主机失败次数

Local_Count=0 #本地主机扫描模式总扫描次数

Local_Connected_Count=0 #本地主机扫描模式结果为Connected的次数

Local_Refused_Count=0 #本地主机扫描模式结果为Refused的次数

Local_Close_Count=0 #本地主机扫描模式结果为Close的次数

Mask_size_Min=20 #可变长子网掩码最小值

Mask_size_Max=32 #可变长子网掩码最大值

Port_Number_Min=1 #端口号最小值

Port_Number_Max=65535 #端口号最大值

Timeout_Second_Min=1 #timeout命令超时最小秒值

Timeout_Second_Max=10 #timeout命令超时最大秒值

Destination_Ip_Count_Min=1 #目的IP地址数量最小值

Destination_Ip_Count_Max=500 #目的IP地址数量最大值

Port_Number_Count_Min=1 #端口数量最小值

Port_Number_Count_Max=500 #端口数量最大值

Source_Ip_Count_Min=1 #源IP地址数量最小值

Source_Ip_Count_Max=500 #源IP地址数量最大值

# >>>>>>>>>>>>>>>>>>>>>>>>全局变量>>>>>>>>>>>>>>>>>>>>>>>>

# >>>>>>>>>>>>>>>>>>>>>>>>全部函数>>>>>>>>>>>>>>>>>>>>>>>>

#函数功能：显示帮助
show_Help(){
  cat <<EOF
用法:
$0 [--pd] [--ssh] [--sourcefile /path/to/source/ip/file] [--destfile /path/to/destination/ip/file] [-s source_ip_format] [-d destination_ip_format] [-p port]  [-t timeout_second] [-h]
--pd
 开启pseudo device扫描模式,默认是telnet模式
--ssh
 开启本地主机扫描模式，默认开启本地主机模式，要与-s参数搭配使用进行远程主机扫描
-t 超时时间
 timeout命令结束的时间,单位为秒,不设置则取脚本中Default_Telnet_Time_Out_Second变量默认值
-s 源IP地址
 源IP地址是用于从跳板机ssh登录的远程主机IP，要与--ssh参数搭配使用进行远程主机扫描，ssh要免密，不然会被认为ssh连接失败。ip格式支持3种:1是192.168.1.1;2是192.168.1-254;3是192.168.1.1/24(cidr),这3种格式的任意一种格式可以利用逗号区分并组合在一起，例子如:-s 192.168.1.1,192.168.15、-s 192.168.1.1,192.168.1.15-20,192.168.1.0/25。
-d 目的IP地址
 格式和源IP地址一样。
--sourcefile 源IP地址所在的文件路径
 如果源IP地址很多而且没有规律，这个场景可以把这些IP放到一个文件中，一行建议只写一种IP格式。
--destfile 目的IP地址所在的文件路径
 要求与--sourcefile参数一样
-p 端口
 端口格式支持2种：1是80；2是1000-1050，这2种格式的任意一种格式可以利用逗号区分并组合在一起,例子如:-p 22,80,443、-p 80,443,1080-1090,9090-9095。
-h 显示帮助

演示例子
1. 本地主机扫描
IP直接为参数进行本地主机扫描模式,使用telnet模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5

IP直接为参数进行本地主机扫描模式,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh --pd -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5

IP以文件形式作为参数进行本地扫描模式,使用telnet模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5

IP以文件形式作为参数进行本地扫描模式,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh --pd --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5

2. 远程主机扫描模式
IP直接为参数进行远程主机扫描模式,-s参数中远程主机IP已做好ssh免密,使用telnet模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh --ssh -s 192.168.122.11,192.168.122.12/31,192.168.122.14-15 -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5

IP直接为参数进行远程主机扫描模式,-s参数中远程主机IP已做好ssh免密,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh --ssh --pd -s 192.168.122.11,192.168.122.12/31,192.168.122.14-15 -d 223.5.5.5,183.3.226.35,192.168.122.11,127.0.0.1 -p 22,53,80-82 -t 5

IP以文件形式作为参数进行远程主机扫描模式,-s参数中远程主机IP已做好ssh免密,使用telnet模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh --ssh --sourcefile ~/source_ip.confg --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5

IP以文件形式作为参数进行远程主机扫描模式,-s参数中远程主机IP已做好ssh免密,使用pseudo device模式,命令演示(超时时间设置为5秒)如下:
bash ./scan_ports.sh --ssh --pd --sourcefile ~/source_ip.confg --destfile ~/destinatioin_ip.config -p 22,53,80-82 -t 5

EOF
  exit
}

#函数功能：显示错误代码解释
show_Error_Codes(){
  cat <<EOF
错误代码解释:
ERR-1:IP格式输入错误,请检查格式与帮助(-h)中格式一致!
ERR-2:目的IP地址数量限制为${Destination_Ip_Count_Min}-${Destination_Ip_Count_Max}，扫描端口(-p)数量范围限制为${Port_Number_Count_Min}-${Port_Number_Count_Max}，telnet超时而被timeout结束的时间(-t)限制为${Timeout_Second_Min}-${Timeout_Second_Max}秒，如果是远程主机扫描模式,源IP地址数量限制范围为${Source_Ip_Count_Min}-${Source_Ip_Count_Max}。IP的范围格式数值限制范围为0～255，IP的cidr格式的可变长子网掩码数值限制为${Mask_size_Min}-${Mask_size_Max}(内网大于20网络划分以上没有意义)。端口范围格式数值限制为${Port_Number_Min}-${Port_Number_Max}。如果你IP数量很多,请分多次后台或多个终端界面跑脚本。
ERR-3:IP和端口范围格式，范围结束值不能小于范围起始值。如192.168.1.12-15中15大于12、1080-1085中1085大于1080。
ERR-4:源IP地址所在的文件路径(--sourcefile)或目的IP地址所在的文件路径(--destfile)不存在！
ERR-5:源IP地址所在的文件路径(--sourcefile)或目的IP地址所在的文件路径(--destfile)不可读！
ERR-6:脚本参数值(-t)为空或没有输入会导致脚本退出！
ERR-7:某些命令(ssh、telnet、timeout)没有安装！
EOF
  exit
}

#函数功能：检测参数1是否存在
#需要1个参数：所要检测的命令
check_Command_Exsit(){
  local temp_command="$1"
  if ! [ -x "$( command -v "${temp_command}" )" ]; then
    echo "ERR-7:${temp_command}"
    show_Error_Codes
  fi
}

#函数功能：脚本初始化检测，telnet、timeout命令是否存在，脚本所在目录是否有写权限
initial(){
  cd "${BaseDir}" || exit
  check_Command_Exsit timeout
  [[ ! -w "${BaseDir}" ]] && exit
}

#函数功能：过滤$1中的前后空格，这里主要用于处理源、目的IP地址所在的文件路径中IP数据前后空格
#需要1个参数：所需要过滤的字符
trim() {
  local var=$1
  var=${var##+([[:space:]])}
  var=${var%%+([[:space:]])}
  echo -n "$var"
}

#函数功能：检测一个数字是否在非负整数集合范围内
#所需参数1：所需检测的数字
#所需参数2：非负整数集合范围起始值(包含)
#所需参数3：非负整数集合范围结束值(包含)
valid_Number_Range(){
  local temp_number="$1"
  local temp_min_number="$2"
  local temp_max_number="$3"
  
  if [ -z "$temp_number" ]; then
    echo "ERR-6"
    show_Error_Codes
  else
    if [[ ${temp_number} =~ ^[0-9]+$ ]] ;then
      if ! (( (( temp_number >= temp_min_number )) &&  (( temp_number <= temp_max_number )) )); then
        echo "ERR-2"
        show_Error_Codes
      fi
    else
        echo "ERR-2"
        show_Error_Codes
	  fi
  fi
}

#函数功能：检测参数1是否是一个合理的IP地址
#所需参数1：所要检测的IP
valid_Ip(){ 
    local ip=$1 
    local stat=1
 
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then 
        IFS='.' read -r -a ip <<<  "$ip"
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]] 
        stat=$? 
    fi

    if (( stat != 0 )); then
      echo "ERR-1:${ip[*]}"
      show_Error_Codes
    fi
} 

#函数功能：把IP范围格式参数1生成范围内IP
#所需参数1：IP范围格式
generate_Ip_ranges() {
  local tmp_argument="$1"
  local a b c

  IFS=- read -r begin_ip end_ip_number <<< "$tmp_argument"
  IFS=. read -r a b c start_ip_number <<< "$begin_ip"
  
  valid_Number_Range "$start_ip_number" 0 255
  valid_Number_Range "$end_ip_number" 0 255

  if (( start_ip_number >= end_ip_number )); then
    echo "ERR-3"
    show_Error_Codes
  fi

  eval "echo ${a}.${b}.${c}.{$start_ip_number..$end_ip_number}"
}

#函数功能：把IP的cidr格式参数1生成范围内IP
#所需参数1：IP的cidr格式
cidr_Tansfer_To_Ip_Ranges(){
  local cidr="$1"
  base=${cidr%/*}
  masksize=${cidr#*/}

  valid_Number_Range "$masksize" "${Mask_size_Min}" "${Mask_size_Max}"
  
  mask=$(( 0xFFFFFFFF << (32 - masksize) ))
  
  IFS=. read -r a b c d <<< "$base"
  
  tmp_ip=$(( (b << 16) + (c << 8) + d ))
  
  ipstart=$(( tmp_ip & mask ))
  ipend=$(( (ipstart | ~mask ) & 0x7FFFFFFF ))
  
  seq $ipstart $ipend | while read -r i; do
      echo "$a".$(( (i & 0xFF0000) >> 16 )).$(( (i & 0xFF00) >> 8 )).$(( i & 0x00FF ))
  done
}

#函数功能：处理IP几种格式核心处理调用函数
deal_With_Ip_Format(){
  local cs_ip="$1"
  case "$cs_ip" in
    *-*)
      for ip in $(generate_Ip_ranges "${cs_ip}") ; do
      if valid_Ip "$ip" ; then 
      eval "$2+=('$ip')"
      fi
      done 
    ;;
    */*)
      for ip in $(cidr_Tansfer_To_Ip_Ranges "${cs_ip}") ; do
        if valid_Ip "$ip" ; then
          eval "$2+=('$ip')"
        fi
      done
    ;;
    *)
      if valid_Ip "$cs_ip" ; then 
        eval "$2+=('$cs_ip')"
      fi
    ;;
  esac
}

#函数功能：处理脚本参数中IP的几种IP格式
check_Ip_Parameter(){
  case "$1" in
    *,*)
      IFS=, read -ra cs_ips <<< "$1"
      for cs_ip in "${cs_ips[@]}";do
        deal_With_Ip_Format "$cs_ip" "$2"
      done
      ;;
    *)
      deal_With_Ip_Format "$1" "$2"
      ;;
  esac
}

#函数功能：处理源、目的IP地址所在的文件路径中IP数据
check_File_Parameter(){
  local file_path="$1"

  if [ ! -f "${file_path}" ]; then
    echo "ERR-4:${file_path}"
    show_Error_Codes
  fi

  if [ ! -r "${file_path}" ]; then
    echo "ERR-5:${file_path}"
    show_Error_Codes
  fi

  IFS=$'\n' read -d '' -ra source_ips < "${file_path}"

  for ip in "${source_ips[@]}" ; do
    ip=$(trim "$ip")
    check_Ip_Parameter "${ip}" "$2"
  done 
  
}

#函数功能：处理端口几种格式核心处理调用函数
deal_With_Ports_Format(){
  local cs_port="$1"
  
  case "$cs_port" in
    *-*)
      IFS=- read -r start end <<< "$cs_port"

      valid_Number_Range "$start" "${Port_Number_Min}" "${Port_Number_Max}"
      valid_Number_Range "$end" "${Port_Number_Min}" "${Port_Number_Max}"

      if (( start >= end )); then
        echo "ERR-3"
        show_Error_Codes
      fi
      
      for ((for_port=start; for_port <= end; for_port++)); do
        All_Ports+=("$for_port")
      done
    ;;
    *)
      valid_Number_Range "$cs_port" "${Port_Number_Min}" "${Port_Number_Max}"
      All_Ports+=("$cs_port")
    ;;
  esac
}

#函数功能：处理脚本参数中端口的几种端口格式
check_Ports(){
  case $1 in
    *,*)
      IFS=, read -ra cs_ports <<< "$1"
      for cs_port in "${cs_ports[@]}";do
        deal_With_Ports_Format "$cs_port"
      done
      ;;
    *)
      deal_With_Ports_Format "$1"
      ;;
  esac
}

#函数功能：用于远程主机扫描核心处理和输出
base_On_SSH_Scan_Engine(){
  if [ "${Pseudo_Scan_Engine}" = "TRUE" ]; then
    mkdir -p "${Ssh_Pd_Scan_Result}"
  else
    mkdir -p "${Ssh_Telnet_Scan_Result}"
  fi
  printf "%-15b%-35b%-20b%-12b%-b\n" "序号" "源地址" "目的地址" "端口" "结果"
  for source_hosts in "${All_Source_Ip[@]}" ; do
    #检测本地主机与远程主机是否免密
    ssh -q -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no "${source_hosts}" 'exit 0'
    local ssh_status=$?
    if (( ssh_status == 0 )); then
      ((Sucess_Ssh_Server+=1))
      source_hosts_hostname=$(ssh "${source_hosts}" 'hostname')
    else
      ((Failed_Ssh_Server+=1))
      printf "${YELLOW}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}" "(${Failed_Ssh_Server})" "Localhost login to" "${source_hosts}" "ssh" "Failed" 
      continue
    fi
    for dest_hosts in "${All_Destination_Ip[@]}" ; do
      for scan_ports in "${All_Ports[@]}" ; do
        if [ "${Pseudo_Scan_Engine}" = "TRUE" ]; then
          # shellcheck disable=SC2029
          if ssh "${source_hosts}" "timeout ${Telnet_Time_OUT_Second} bash -c \"</dev/tcp/${dest_hosts}/${scan_ports}\" && exit 0 || exit 1" > /dev/null 2>&1 ;then
            ((Ssh_Count+=1))
            ((Ssh_Connected_Count+=1))
            printf  "${GREEN}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}" "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "Connected" | tee -a "${Ssh_Pd_Scan_Connected_Log}"
          else
            ((Ssh_Count+=1))
            ((Ssh_Close_Count+=1))
            printf  "${RED}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}"   "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "Close" | tee -a "${Ssh_Pd__Scan_Close_Log}"
          fi
        else
          Per_Telnet_Result=${Ssh_Telnet_Scan_Result}/remote_${source_hosts}_to_${dest_hosts}_${scan_ports}_result_$(date +%Y%m%d%H%M%S%N).log
          ssh -t "${source_hosts}" "timeout --foreground ${Telnet_Time_OUT_Second} telnet ${dest_hosts} ${scan_ports}" > "${Per_Telnet_Result}" 2>&1
          if grep -wq 'Connected' "${Per_Telnet_Result}" ; then
            ((Ssh_Count+=1))
            ((Ssh_Connected_Count+=1))
            printf  "${GREEN}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}" "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "Connected" | tee -a "${Ssh_Telnet_Connected_Log}"
          elif grep -wq 'refused' "${Per_Telnet_Result}" ;then
            ((Ssh_Count+=1))
            ((Ssh_Refused_Count+=1))
            printf  "${BLUE}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}"  "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "refused" | tee -a "${Ssh_Telnet_Refuse_Log}"
          else
            ((Ssh_Count+=1))
            ((Ssh_Close_Count+=1))
            printf  "${RED}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}"   "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "Close" | tee -a "${Ssh_Telnet_Close_Log}"
          fi
        fi
      done
    done
  done
}

#函数功能：用于本地主机扫描核心处理和输出
base_On_Local_Scan_Engine(){
  if [ "${Pseudo_Scan_Engine}" = "TRUE" ]; then
    mkdir -p "${Local_Pd_Scan_Result}"
  else
    mkdir -p "${Local_Telnet_Scan_Result}"
  fi
  printf "%-15b%-18b%-22b%-12b%-b\n" "序号" "源地址" "目的地址" "端口" "结果"
  for dest_hosts in "${All_Destination_Ip[@]}" ; do
    for scan_ports in "${All_Ports[@]}" ; do
      if [ "${Pseudo_Scan_Engine}" = "TRUE" ]; then
        if timeout "${Telnet_Time_OUT_Second}" bash -c "</dev/tcp/${dest_hosts}/${scan_ports} " 2>/dev/null ;then
          ((Local_Count+=1))
          ((Local_Connected_Count+=1))
          printf  "${GREEN}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}" "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "Connected" | tee -a "${Local_Pd_Scan_Connected_Log}"
        else
          ((Local_Count+=1))
          ((Local_Close_Count+=1))
          printf  "${RED}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}"   "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "Close"  | tee -a "${Local_Pd_Scan_Close_Log}"
        fi
      else
        Per_Telnet_Result=${Local_Telnet_Scan_Result}/localhost_to_${dest_hosts}_${scan_ports}_result_$(date +%Y%m%d%H%M%S%N).log
        timeout "${Telnet_Time_OUT_Second}" telnet "${dest_hosts}" "${scan_ports}" > "${Per_Telnet_Result}" 2>&1
        if grep -wq 'Connected' "${Per_Telnet_Result}" ; then
          ((Local_Count+=1))
          ((Local_Connected_Count+=1))
          printf  "${GREEN}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}" "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "Connected" | tee -a "${Local_Telnet_Connected_Log}"
        elif grep -wq 'refused' "${Per_Telnet_Result}" ;then
          ((Local_Count+=1))
          ((Local_Refused_Count+=1))
          printf  "${BLUE}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}"  "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "refused" | tee -a "${Local_Telnet_Refuse_Log}"
        else
          ((Local_Count+=1))
          ((Local_Close_Count+=1))
          printf  "${RED}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}"   "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "Close" | tee -a "${Local_Telnet_Close_Log}"
        fi
      fi
    done
  done
}

#函数功能：用于呈现远处主机扫描结果报告
build_Ssh_Scan_Report(){
  printf "Report:\n总源IP地址数量:%d,总目的IP地址数量:%d,总扫描端口数量:%d,总扫面端口次数:%d\n" "${#All_Source_Ip[@]}" "${#All_Destination_Ip[@]}" "${#All_Ports[@]}" "${Ssh_Count}"
  printf "扫描结果为Connected的端口数量:%d\n" "${Ssh_Connected_Count}"
  printf "扫描结果为Refused的端口数量:%-50d\n" "${Ssh_Refused_Count}"
  printf "扫描结果为Close的端口数量:%d\n" "${Ssh_Close_Count}"
  printf "ssh成功登录远程主机数量:%d\n" "${Sucess_Ssh_Server}"
  printf "ssh失败登录远程主机数量:%d,导致无法扫描的端口数量:%d\n" "${Failed_Ssh_Server}" "$(( Failed_Ssh_Server * ${#All_Destination_Ip[@]} * ${#All_Ports[@]} ))"
  if [ "${Pseudo_Scan_Engine}" = "TRUE" ]; then
    printf "ssh到远程主机pseudo device扫描模式的结果目录:%s\n" "${Ssh_Pd_Scan_Result}"
  else
    printf "ssh到远程主机telnet扫描模式的结果目录:%s\n" "${Ssh_Telnet_Scan_Result}"
  fi
}

#函数功能：用于呈现本地主机扫描结果报告
build_Local_Scan_Report(){
  printf "Report:\n总目的IP地址数量:%d\t总扫描端口数量:%d\t总扫面端口次数:%d\n" "${#All_Destination_Ip[@]}" "${#All_Ports[@]}" "${Local_Count}"
  printf "扫描结果为Connected的端口数量:%d\n" "${Local_Connected_Count}"
  printf "扫描结果为Refused的端口数量:%-50d\n" "${Local_Refused_Count}"
  printf "扫描结果为Close的端口数量:%d\n" "${Local_Close_Count}"
  if [ "${Pseudo_Scan_Engine}" = "TRUE" ]; then
    printf "本地主机pseudo device扫描模式的结果目录:%s\n" "${Local_Pd_Scan_Result}"
  else
    printf "在本地主机telnet扫描模式的结果目录:%s\n" "${Local_Telnet_Scan_Result}"
  fi
}

#函数功能：主函数用处判断脚本参数并调用其他函数
main(){
  initial

  local POSITIONAL=()

  (( $# == 0 )) && show_Help

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sourcefile)
        local sourcefile="$2"
        check_File_Parameter "${sourcefile}" "All_Source_Ip"
        #echo "${All_Source_Ip[*]}"
        shift 2
      ;;
      -s)
        local source_ip_tmp="$2"
        check_Ip_Parameter "${source_ip_tmp}"  "All_Source_Ip"
        #echo "${All_Source_Ip[*]}"
        shift 2
      ;;
      --destfile)
        local destfile="$2"
        check_File_Parameter "${destfile}" "All_Destination_Ip"
        #echo "${All_Destination_Ip[*]}"
        shift 2
      ;;
      -d)
        local destination_ip_tmp="$2"
        check_Ip_Parameter "${destination_ip_tmp}" "All_Destination_Ip"
        #echo "${All_Destination_Ip[*]}"
        shift 2
      ;;
      -p)
        port_tmp="$2"
        check_Ports "${port_tmp}"
        #echo "${All_Ports[@]}"
        shift 2
      ;;
      -h)
        show_Help
        shift
      ;;
      -t)
        Telnet_Time_OUT_Second="$2"
        valid_Number_Range "$Telnet_Time_OUT_Second" "${Timeout_Second_Min}" "${Timeout_Second_Max}"
        shift 2
      ;;
      --ssh)
        Ssh_Scan_Mode='TRUE'
        shift
      ;;
      --pd)
        Pseudo_Scan_Engine='TRUE'
        shift
      ;;
      *)
        POSITIONAL+=("$1")
        set -- "${POSITIONAL[@]}"
        echo "Illegal Argument:${POSITIONAL[*]}"
        show_Help
        shift
      ;;
    esac
  done

  #限制目的IP地址数量和端口数量
  valid_Number_Range "${#All_Destination_Ip[@]}" "${Destination_Ip_Count_Min}" "${Destination_Ip_Count_Max}"
  valid_Number_Range "${#All_Ports[@]}" "${Port_Number_Count_Min}" "${Port_Number_Count_Max}"

  Telnet_Time_OUT_Second="${Telnet_Time_OUT_Second:-$Default_Telnet_Time_Out_Second}"
  valid_Number_Range "${Telnet_Time_OUT_Second}" "${Timeout_Second_Min}" "${Timeout_Second_Max}"

  if [ "${Pseudo_Scan_Engine}" = "FALSE" ] ; then
    check_Command_Exsit telnet
  fi

  if [ "${Ssh_Scan_Mode}" = "TRUE" ] ; then
    #限制远程主机模式中源IP地址数量
    valid_Number_Range "${#All_Source_Ip[@]}" "${Source_Ip_Count_Min}" "${Source_Ip_Count_Max}"
    check_Command_Exsit ssh
    base_On_SSH_Scan_Engine
    build_Ssh_Scan_Report  
  else
    All_Source_Ip=()
    base_On_Local_Scan_Engine
    build_Local_Scan_Report
  fi
}
# >>>>>>>>>>>>>>>>>>>>>>>>全部函数>>>>>>>>>>>>>>>>>>>>>>>>

#传参数给主函数处理
main "$@"
