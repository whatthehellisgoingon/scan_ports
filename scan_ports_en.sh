#!/usr/bin/env bash


# >>>>>>>>>>>>>>>>>>>>>>>> Global Variables Start>>>>>>>>>>>>>>>>>>>>>>>>
#shell script location directory
BaseDir=$(cd "$(dirname "$0")" && pwd || exit)

#per telnet scan result path
Result_Dir=${BaseDir}/result

#telnet time out seconds
Default_Telnet_Time_Out_Second=3
Telnet_Time_OUT_Second=""

#set localhost scan mode default value is false
Localhost_Scan_Mode='FALSE'

#Array
All_Source_Ip=()
All_Destination_Ip=()
All_Ports=()

#print color
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
NORMAL=$(tput sgr0)

#report cout
Ssh_Count=0
Ssh_Connected_Count=0
Ssh_Refused_Count=0
Ssh_Close_Count=0

Local_Count=0
Local_Connected_Count=0
Local_Refused_Count=0
Local_Close_Count=0

Sucess_Ssh_Server=0
Failed_Ssh_Server=0

# >>>>>>>>>>>>>>>>>>>>>>>> Global Variables End >>>>>>>>>>>>>>>>>>>>>>>>

# >>>>>>>>>>>>>>>>>>>>>>>> All Functions Start >>>>>>>>>>>>>>>>>>>>>>>>
show_Help(){
  cat <<EOF
usage:
$0 [--sourcefile /path/to/source/ip/file] [--destfile /path/to/destination/ip/file] [-s source_ip_format] [-d destination_ip_format] <-p port>  [-h]
--sourcefile Path to a souce ip file
--destfile Path to a destination ip file
-s source ip format,192.168.0.1 or 192.168.0.1-16(from 192.168.0.1 to 192.168.0.16) or 192.168.0.128/25 or 192.168.0.1,192.168.0.1-16,192.168.0.128/25
-d destination ip format,same as source ip format
-p port format,80 or 1000-2000(from 1000 to 2000) or 22,80(scan 22 and 80) or 20,80,1080-1090,8080,9090(20\80\from 1080 to 1090\8080\9090)
-h display this help and exit
EOF
  exit
}

show_Error_Codes(){
  cat <<EOF
Error Codes Explain:
ERR-1:IP format Error!,please input valid ip format!
ERR-2:port must be a number between 1 to 65535,number of ports between 1 to 10000,number of Ips between 1 to 1000!
ERR-3:Ip or port ranges start number must less then end number!
ERR-4:file is not exsit!
ERR-5:file is not readable!
ERR-6:Option value is empty!
ERR-7:Comand is not installed  in system!
EOF
  exit
}

check_Command_Exsit(){
  local temp_command="$1"
  if ! [ -x "$( command -v "${temp_command}" )" ]; then
    echo "ERR-7:${temp_command}"
    show_Error_Codes
  fi
}

initial(){
  check_Command_Exsit telnet
  check_Command_Exsit timeout
  [[ ! -w "${BaseDir}" ]] && exit
  [[ ! -d "${Result_Dir}" ]] && mkdir -p "${Result_Dir}"
}

trim() {
    local var=$1
    var=${var##+([[:space:]])}
    var=${var%%+([[:space:]])}
    echo -n "$var"
}

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

cidr_Tansfer_To_Ip_Ranges(){
  local cidr="$1"
  base=${cidr%/*}
  masksize=${cidr#*/}

  valid_Number_Range "$masksize" 16 32
  
  mask=$(( 0xFFFFFFFF << (32 - masksize) ))
  
  IFS=. read -r a b c d <<< "$base"
  
  tmp_ip=$(( (b << 16) + (c << 8) + d ))
  
  ipstart=$(( tmp_ip & mask ))
  ipend=$(( (ipstart | ~mask ) & 0x7FFFFFFF ))
  
  seq $ipstart $ipend | while read -r i; do
      echo "$a".$(( (i & 0xFF0000) >> 16 )).$(( (i & 0xFF00) >> 8 )).$(( i & 0x00FF ))
  done
}

deal_With_Ip_Format(){
  local cs_ip="$1"
  case "$cs_ip" in
    *-*)
      for ip in $(generate_Ip_ranges "${cs_ip}") ; do
      ip=$(trim "$ip")
      if valid_Ip "$ip" ; then 
      eval "$2+=('$ip')"
      fi
      done 
    ;;
    */*)
      for ip in $(cidr_Tansfer_To_Ip_Ranges "${cs_ip}") ; do
        ip=$(trim "$ip")
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



base_On_SSH_Scan_Engine(){
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
        Per_Telnet_Result=${Result_Dir}/telnet_${source_hosts}_to_${dest_hosts}_${scan_ports}_result_$(date +%Y%m%d%H%M%S%N)
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

base_On_Local_Scan_Engine(){
  printf "%-11b%-15b%-20b%-9b%-11b\n" "Number" "SourceHost" "DestinationHost" "Port" "Result"
  for dest_hosts in "${All_Destination_Ip[@]}" ; do
    for scan_ports in "${All_Ports[@]}" ; do
      Per_Telnet_Result=${Result_Dir}/telnet_localhost_to_${dest_hosts}_${scan_ports}_result_$(date +%Y%m%d%H%M%S%N)
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

build_Ssh_Scan_Report(){
  printf "Report:\nTotal Source Ip Number:%d,Total Destiantion Ip Number:%d,Total Ports:%d,Total Scan Number:%d\n" "${#All_Source_Ip[@]}" "${#All_Destination_Ip[@]}" "${#All_Ports[@]}" "${Ssh_Count}"
  printf "Connected Port Number:%d\n" "${Ssh_Connected_Count}"
  printf "Refused Port Number:%-50d\n" "${Ssh_Refused_Count}"
  printf "Close Port Number:%d\n" "${Ssh_Close_Count}"
  printf "Sucess Login Server Number:%d\n" "${Ssh_Connected_Count}"
  printf "Failed Login Server Number:%d,Failed to scan port number:%d\n" "${Failed_Ssh_Server}" "$(( Failed_Ssh_Server * ${#All_Destination_Ip[@]} * ${#All_Ports[@]} ))"
}

build_Local_Scan_Report(){
  printf "Report:\nTotal Ip Number:%d\tTotal Ports:%d\tTotal Scan Number:%d\n" "${#All_Destination_Ip[@]}" "${#All_Ports[@]}" "${Local_Count}"
  printf "Connected Port Number:%d\n" "${Local_Connected_Count}"
  printf "Refused Port Number:%-50d\n" "${Local_Refused_Count}"
  printf "Close Port Number:%d\n" "${Local_Close_Count}"
}

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
  valid_Number_Range "${#All_Ports[@]}" 1 10000

  Telnet_Time_OUT_Second="${Telnet_Time_OUT_Second:-$Default_Telnet_Time_Out_Second}"
  valid_Number_Range "$Telnet_Time_OUT_Second" 1 20

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
# >>>>>>>>>>>>>>>>>>>>>>>> All Functions End>>>>>>>>>>>>>>>>>>>>>>>>

main "$@"