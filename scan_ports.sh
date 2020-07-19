#!/usr/bin/env bash


# >>>>>>>>>>>>>>>>>>>>>>>>全局变量>>>>>>>>>>>>>>>>>>>>>>>>
#脚本所在目录
BaseDir=$(cd "$(dirname "$0")" && pwd || exit)

#telnet结果的总目录
Result_Dir=${BaseDir}/result
#在本地主机扫描的结果目录
Local_Telnet_Scan_Result=${Result_Dir}/local_telnet_scan_result_$(date +%Y%m%d%H%M%S)
#ssh到远程主机扫描的结果目录
Ssh_Telnet_Scan_Result=${Result_Dir}/ssh_telnet_scan_result_$(date +%Y%m%d%H%M%S)

#telnet超时而被timeout结束的默认时间
Default_Telnet_Time_Out_Second=3
Telnet_Time_OUT_Second=""

#本地主机扫描模式开关,默认是关闭的
Localhost_Scan_Mode='FALSE'

#初始化数组
#源IP地址数组
All_Source_Ip=()
#目的IP地址数组
All_Destination_Ip=()
#所扫描端口的数组
All_Ports=()

#颜色设置
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
NORMAL=$(tput sgr0)

#初始化扫描报告统计数值变量
#ssh远程主机扫描模式统计数值变量
Ssh_Count=0
Ssh_Connected_Count=0
Ssh_Refused_Count=0
Ssh_Close_Count=0
Sucess_Ssh_Server=0
Failed_Ssh_Server=0
#本地主机扫描模式统计数值变量
Local_Count=0
Local_Connected_Count=0
Local_Refused_Count=0
Local_Close_Count=0

# >>>>>>>>>>>>>>>>>>>>>>>>全局变量>>>>>>>>>>>>>>>>>>>>>>>>

# >>>>>>>>>>>>>>>>>>>>>>>>全部函数>>>>>>>>>>>>>>>>>>>>>>>>

#函数功能：显示帮助
show_Help(){
  cat <<EOF
用法:
$0 [-l] [-t timeout_second] [--sourcefile /path/to/source/ip/file] [--destfile /path/to/destination/ip/file] [-s source_ip_format] [-d destination_ip_format] [-p port] [-h]
-l 开启本地主机扫描模式 当开启本地主机模式，注意：-s、--sourcefile参数里面源IP将回失去作用！
-t 设置telnet超时而被timeout命令结束的时间 不设置则取变量默认值
-s 源IP地址 要用于从跳板机ssh登录的远程主机，ssh要免密，不然还是使用本地主机模式。ip格式支持3种:1是192.168.1.1;2是192.168.1-254;3是192.168.1.1/24(cidr),这3种格式的任意一种格式可以利用逗号区分并组合在一起,例子如:-s 192.168.1.1,192.168.15、-s 192.168.1.1,192.168.1.15-20,192.168.1.0/25。
-d 目的IP地址 格式和源IP地址一样。
--sourcefile 源IP地址所在的文件路径 如果源IP地址很多而且没有规律，这个场景可以把这些IP放到一个文件中，一行建议只写一种IP格式。
--destfile 目的IP地址所在的文件路径 要求与--sourcefile参数一样
-p 端口 端口格式支持2种：1是80；2是1000-1050，这2种格式的任意一种格式可以利用逗号区分并组合在一起,例子如:-p 22,80,443、-p 80,443,1080-1090,9090-9095。
-h 显示帮助
EOF
  exit
}

#函数功能：显示错误代码解释
show_Error_Codes(){
  cat <<EOF
错误代码解释:
ERR-1:IP格式输入错误,请检查格式与帮助(-h)中格式一致!
ERR-2:目的IP地址数量限制为1～1000，扫描端口(-p)数量范围限制为1-1000，telnet超时而被timeout结束的时间(-t)限制为1-10秒，如果是远程主机扫描模式,源IP地址数量限制范围为1～1000。IP的范围格式数值限制范围为0～255，IP的cidr格式的可变长子网掩码数值限制为20-32(内网大于20网络划分以上没有意义)。端口范围格式数值限制为1-65535。
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
  check_Command_Exsit telnet
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
    local ip_error_code="ERR-1"
 
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then 
        IFS='.' read -r -a ip <<<  "$ip"
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]] 
        stat=$? 
    fi

    if (( stat != 0 )); then
      echo "${ip_error_code}:${ip[*]}"
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

  valid_Number_Range "$masksize" 20 32
  
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

      valid_Number_Range "$start" 1 65535
      valid_Number_Range "$end" 1 65535

      if (( start >= end )); then
        echo "ERR-3"
        show_Error_Codes
      fi
      
      for ((for_port=start; for_port <= end; for_port++)); do
        All_Ports+=("$for_port")
      done
    ;;
    *)
      valid_Number_Range "$cs_port" 1 65535
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
  mkdir -p "${Ssh_Telnet_Scan_Result}"
  printf "%-11b%-30b%-20b%-9b%-11b\n" "Number" "SourceHost" "DestinationHost" "Port" "Result"
  for source_hosts in "${All_Source_Ip[@]}" ; do
    ssh -q -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no "hello@${source_hosts}" 'exit 0'
    local ssh_status=$?
    if (( ssh_status == 0 )); then
      ((Sucess_Ssh_Server+=1))
      source_hosts_hostname=$(ssh hello@"${source_hosts}" 'hostname')
    else
      ((Failed_Ssh_Server+=1))
      printf "${YELLOW}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}" "(${Failed_Ssh_Server})" "Localhost login to" "${source_hosts}" "ssh" "Failed" 
      continue
    fi
    for dest_hosts in "${All_Destination_Ip[@]}" ; do
      for scan_ports in "${All_Ports[@]}" ; do
        Per_Telnet_Result=${Ssh_Telnet_Scan_Result}/remote_${source_hosts}_to_${dest_hosts}_${scan_ports}_result_$(date +%Y%m%d%H%M%S%N).log
        timeout --foreground ${Telnet_Time_OUT_Second} ssh -t "${source_hosts}" "echo '\r' | telnet ${dest_hosts} ${scan_ports}" > "${Per_Telnet_Result}" 2>&1
        if grep -wq 'Connected' "${Per_Telnet_Result}" ; then
          ((Ssh_Count+=1))
          ((Ssh_Connected_Count+=1))
          printf  "${GREEN}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}" "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "Connected"
        elif grep -wq 'refused' "${Per_Telnet_Result}" ;then
          ((Ssh_Count+=1))
          ((Ssh_Refused_Count+=1))
          printf  "${BLUE}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}"  "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "refused"
        else
          ((Ssh_Count+=1))
          ((Ssh_Close_Count+=1))
          printf  "${RED}%-11b%-30b%-20b%-9b%-11b\n${NORMAL}"   "(${Ssh_Count})" "(${source_hosts_hostname})${source_hosts}" "${dest_hosts}" "${scan_ports}" "Close"
        fi
      done
    done
  done
}

#函数功能：用于本地主机扫描核心处理和输出
base_On_Local_Scan_Engine(){
  mkdir -p "${Local_Telnet_Scan_Result}"
  printf "%-11b%-15b%-20b%-9b%-11b\n" "Number" "SourceHost" "DestinationHost" "Port" "Result"
  for dest_hosts in "${All_Destination_Ip[@]}" ; do
    for scan_ports in "${All_Ports[@]}" ; do
      Per_Telnet_Result=${Local_Telnet_Scan_Result}/localhost_to_${dest_hosts}_${scan_ports}_result_$(date +%Y%m%d%H%M%S%N).log
      timeout ${Telnet_Time_OUT_Second} telnet "${dest_hosts}" "${scan_ports}" > "${Per_Telnet_Result}" 2>&1
      if grep -wq 'Connected' "${Per_Telnet_Result}" ; then
        ((Local_Count+=1))
        ((Local_Connected_Count+=1))
        printf  "${GREEN}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}" "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "Connected"
      elif grep -wq 'refused' "${Per_Telnet_Result}" ;then
        ((Local_Count+=1))
        ((Local_Refused_Count+=1))
        printf  "${BLUE}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}"  "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "refused"
      else
        ((Local_Count+=1))
        ((Local_Close_Count+=1))
        printf  "${RED}%-11b%-15b%-20b%-9b%-11b\n${NORMAL}"   "(${Local_Count})" "localhost" "${dest_hosts}" "${scan_ports}" "Close"
      fi
    done
  done
  
}

#函数功能：用于呈现远处主机扫描结果报告
build_Ssh_Scan_Report(){
  printf "Report:\nTotal Source Ip Number:%d,Total Destiantion Ip Number:%d,Total Ports:%d,Total Scan Number:%d\n" "${#All_Source_Ip[@]}" "${#All_Destination_Ip[@]}" "${#All_Ports[@]}" "${Ssh_Count}"
  printf "Connected Port Number:%d\n" "${Ssh_Connected_Count}"
  printf "Refused Port Number:%-50d\n" "${Ssh_Refused_Count}"
  printf "Close Port Number:%d\n" "${Ssh_Close_Count}"
  printf "Sucess Login Server Number:%d\n" "${Ssh_Connected_Count}"
  printf "Failed Login Server Number:%d,Failed to scan port number:%d\n" "${Failed_Ssh_Server}" "$(( Failed_Ssh_Server * ${#All_Destination_Ip[@]} * ${#All_Ports[@]} ))"
}

#函数功能：用于呈现本地主机扫描结果报告
build_Local_Scan_Report(){
  printf "Report:\nTotal Ip Number:%d\tTotal Ports:%d\tTotal Scan Number:%d\n" "${#All_Destination_Ip[@]}" "${#All_Ports[@]}" "${Local_Count}"
  printf "Connected Port Number:%d\n" "${Local_Connected_Count}"
  printf "Refused Port Number:%-50d\n" "${Local_Refused_Count}"
  printf "Close Port Number:%d\n" "${Local_Close_Count}"
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
        valid_Number_Range "$Telnet_Time_OUT_Second" 1 20
        shift 2
      ;;
      -l)
        Localhost_Scan_Mode='TRUE'
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

  valid_Number_Range "${#All_Destination_Ip[@]}" 1 1000
  valid_Number_Range "${#All_Ports[@]}" 1 1000

  Telnet_Time_OUT_Second="${Telnet_Time_OUT_Second:-$Default_Telnet_Time_Out_Second}"
  valid_Number_Range "$Telnet_Time_OUT_Second" 1 10

  if [ "$Localhost_Scan_Mode" = "TRUE" ]; then
    All_Source_Ip=()
    base_On_Local_Scan_Engine
    build_Local_Scan_Report
  else
    valid_Number_Range "${#All_Source_Ip[@]}" 1 1000
    check_Command_Exsit ssh
    base_On_SSH_Scan_Engine
    build_Ssh_Scan_Report
  fi
}
# >>>>>>>>>>>>>>>>>>>>>>>>全部函数>>>>>>>>>>>>>>>>>>>>>>>>

#传参数给主函数处理
main "$@"