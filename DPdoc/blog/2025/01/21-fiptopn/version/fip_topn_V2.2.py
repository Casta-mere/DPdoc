import argparse
import ConfigParser
import os
import paramiko
import re
import time
from ReadConfig import readDP, readDB
from ConnectDb import MySQL, RESOURCE_TYPE
from ConnectDb import DPTECH_DUMMY_IP_ALLOCATIONS as DMIP

IP_PATTERN = r"IP Address:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
SESSION_PATTERN = r"Session Number:(\d+)"
CPU_FILE = '/var/lib/neutron/cpu.txt'
FWAAS_CONF = '/etc/neutron/fwaas_driver.ini'
NEUTRON_CONFIG = "/etc/neutron/neutron.conf"
# DP_CONFIG = "./config.ini"
DP_CONFIG = "/home/deployer/RG_Check/DP/config.ini"

def read_ini(filename):
    """
    Read configuration from ini file.
    :param filename: filename of the ini file
    """

    config = ConfigParser.ConfigParser()
    if not os.path.exists(filename):
        print("file %s not exist", filename)
        exit(0)
    config.read(filename)
    return config

class SSH_dp(object):
    def __init__(self, ip, port, username, password):
        """SSH connect """
        try:
            self.ip = ip
            self.port = port
            self.username = username
            self.password = password
            self.connect = True
            self.transport = paramiko.Transport((ip, port))
            self.transport.connect(username=username, password=password)
            self.channel = self.transport.open_session()
            self.channel.settimeout(864000)
            self.channel.get_pty('vt100')
            self.channel.invoke_shell()
            print(self.ip + ' connect success')
        except Exception as e:
            print(e)
            self.connect = False
            print(self.ip + ' connect fail !\ncheck ip/username/password!')
            exit(0)

    def excute_cmd(self, cmd):
        self.channel.send(cmd + '\n')
        ssh_shells = ''
        n = 1
        while True:
            try:
                data = self.channel.recv(20480)
            except:
                break
            time.sleep(float(0.2))
            ssh_shells += str(data)

            if '<' in str(data):
                zifu = str(data).strip()
                if zifu[-1] == '>':
                    break
            elif '--More(CTRL+C break)--' in str(data):
                self.channel.send(' ')
            elif '%' in str(data):
                break
            else:
                continue

        return ssh_shells

    def close(self):
        self.channel.close()
        return 'close success'

def get_device_info(device_info):
    ssh_dp = SSH_dp(device_info['device_ip'], 22, device_info['username'], device_info['password'])
    return_cmd = ssh_dp.excute_cmd("show version")
    # print(return_cmd)

    box_cmd =  ssh_dp.excute_cmd("show session topn src-ip 50")
    box_cmd1 =  ssh_dp.excute_cmd("show session topn dst-ip 50")
    ans = box_cmd + "\n" + box_cmd1
    result = {}
    if("% Unknown command" in ans):
        matches = re.findall(r'\[SLOT\s+(\d+)\]', str(return_cmd))
        slot_numbers = matches
        for j in slot_numbers:
            return_cmd = ssh_dp.excute_cmd("show session topn slot %s src-ip 50" %(j))
            return_cmd1 = ssh_dp.excute_cmd("show session topn slot %s dst-ip 50" %(j))
            ans = return_cmd + "\n" + return_cmd1

    ip_addresses = re.findall(IP_PATTERN, ans)
    session_numbers = re.findall(SESSION_PATTERN, ans)

    for ip, session in zip(ip_addresses, session_numbers):
        if ip in result:
            result[ip] += int(session)
        else:
            result[ip] = int(session)

    ssh_dp.close()
    return result
    
def get_zone(device_ip):
    config = read_ini(FWAAS_CONF)
    for section in config.sections():
        conf = dict(config.items(section))
        if "device_ip" in conf and conf["device_ip"] == device_ip:
            return conf["az"]
        
    return "None"

def get_device_cpu(device_info):
    ssh_dp = SSH_dp(device_info['device_ip'], 22, device_info['username'], device_info['password'])
    with open(CPU_FILE, 'w') as file:
        file.write(device_info['device_ip'] + " cpu " + str(args.cpu) +" session !!!!!!!!!!!!!!!! 10 times at %s \n" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) )

        for i in range(10):
            if args.cpu == "all":
                ssh_dp.excute_cmd("sniffer filter all")
                return_cmd1 = ssh_dp.excute_cmd("sniffer capture session")
                with open(CPU_FILE, 'a') as file:
                    file.write(return_cmd1)
            else:
                cmdd = "sniffer filter vcpu " + args.cpu
                ssh_dp.excute_cmd(cmdd)
                return_cmd1 = ssh_dp.excute_cmd("sniffer capture session")
                with open(CPU_FILE, 'a') as file:
                    file.write(return_cmd1)
    
    print("CPU SNIFFER SUCCESS. result in %s" % CPU_FILE)

def formatOutput(device_ip, device_info):
    data = data_process(device_ip, device_info)
    headers = ["policy_name", "ip", "zone", "session", "speed", "user_id"]
    column_widths = [max(len(str(item)) for item in column) for column in zip(headers, *data)]
    format_str = '| ' + ' | '.join('{{{0}:<{1}}}'.format(i, width) for i, width in enumerate(column_widths)) + ' |'
    width = sum(column_widths) + len(headers) * 3 - 1
    ans = []
    ans.append('+' + '-' * width + '+')
    ans.append(format_str.format(*headers))
    ans.append( '+' + '-' * width + '+')
    for i in data:
        ans.append(format_str.format(*i))
    ans.append( '+' + '-' * width + '+')
    return ans

def data_process(device_ip, device_info):
    filteredData = [(key, device_info[key]) for key in device_info if device_info[key][0] < args.e and device_info[key][0] > args.s]
    sortedData =  sorted(filteredData, key=lambda row: row[1], reverse=True)
    trancatedData = sortedData[:args.n]
    zone = get_zone(device_ip)
    rows = [("FIP_IN_" + i[0], i[0], zone, i[1][0], 0, i[1][1]) for i in trancatedData]
    return rows

def parseArgs(parser):
    parser.add_argument('--cpu', help="choose the device ip to checked from multiple devices", default="all", type=str)
    parser.add_argument('--n', help="show top n devices info, default 30",default=30, type=int)
    parser.add_argument('--s', help="lower bound of session number, default 0",default=0, type=int)
    parser.add_argument('--e', help="upper bound of session number, default 99999999",default=99999999, type=int)

def get_project_id_sql(resource_id, resource_type):
    if resource_type not in RESOURCE_TYPE:
        return None
    return "select project_id from %s where id = '%s';" % (RESOURCE_TYPE[resource_type], resource_id) 
    
def get_project_id(device):
    sql = get_project_id_sql(device[DMIP["resource_id"]][:36], device[DMIP["resource_type"]])
    try:
        project_id = neutronDb.execute_sql(sql)[0][0]
    except Exception as e:
        print(e)
        project_id = None

    return project_id

def write(data):
    date = time.strftime("%Y-%m-%d", time.localtime())
    with open("./res/%s.txt" % date, "a") as f:
        f.write(data)

if __name__ == '__main__':
    os.system("clear")
    write("fip topN at %s\n" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    parser = argparse.ArgumentParser()
    parseArgs(parser)
    args = parser.parse_args()

    neutronUrl = readDB(NEUTRON_CONFIG)
    neutronDb = MySQL(neutronUrl)
    dummy_ips_info = neutronDb.get_dummy_ip()
    dummy_ips = {i[1]: i for i in dummy_ips_info}
    print("There are %s dummy ips" % len(dummy_ips_info))
    write("There are %s dummy ips \n" % len(dummy_ips_info))

    info = readDP(DP_CONFIG)
    devices = info["devices"]
    device_session_ips = []
    for i in devices:
        try:
            device = {
                "device_ip": i,
                "username": info["user"],
                "password": info["password"]
            }
            get_device_cpu(device)
            device_info = get_device_info(device)
            device_info = {i: [device_info[i]] for i in device_info}
            device_session_ips = [i for i in device_info]
            for i in device_session_ips:
                project_id =  "\\"
                if i in dummy_ips:
                    try:
                        project_id = get_project_id(dummy_ips[i])
                    except:
			            pass
                device_info[i].append(project_id)
            print("\n".join(formatOutput(device["device_ip"], device_info)))
            write("Device: %s\n" % device["device_ip"])
            write("\n".join(formatOutput(device["device_ip"], device_info)) + "\n")

        except Exception as e:
            print("Error in %s: %s" % (i, e))
           
    write("==================================================================================\n\n")