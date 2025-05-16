import argparse
import ConfigParser
import os
import paramiko
import re
import time

EXTERNAL_SECTION_HEAD = ('external_', 'dptechnology')
FWAAS_CONF = '/etc/neutron/fwaas_driver.ini'
CPU_FILE = '/var/lib/neutron/cpu.txt'
IP_PATTERN = r"IP Address:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
SESSION_PATTERN = r"Session Number:(\d+)"

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

class PluginHost(object):

    def __init__(self, device_port):
        self.configurations = {}
        self.host_name = self.get_host_name()
        self.get_plugin_conf(device_port)

    def get_plugin_conf(self, device_port):
        conf = read_ini(FWAAS_CONF)
        sections = conf.sections()
        external_sects = [se for se in sections if se.startswith(EXTERNAL_SECTION_HEAD)]
        for external_sect in external_sects:
            device_ip = conf.get(external_sect, 'device_ip')
            username = conf.get(external_sect, 'username')
            password = conf.get(external_sect, 'password')
            az = conf.get(external_sect,'az')
            if device_ip not in self.configurations:
                self.configurations[device_ip] = {
                    'device_ip': device_ip,
                    'username': username,
                    'password': password,
                    'device_port': device_port,
                    'zone': az, 
                }
        # print('get_plugin_conf, host: %s, devices: %s' % (self.host_name, list(self.configurations.keys())))

    @staticmethod
    def get_host_name():
        with open('/etc/hostname', 'r') as f:
            return f.read().strip()

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
        file.write("cpu " +str(args.cpu) +" session !!!!!!!!!!!!!!!! 10 times")

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
    headers = ["policy_name", "ip", "zone", "session", "speed"]
    column_widths = [max(len(str(item)) for item in column) for column in zip(headers, *data)]
    format_str = ' | '.join('{{{0}:<{1}}}'.format(i, width) for i, width in enumerate(column_widths))
    print('-' * (sum(column_widths) + 13) + '+')
    print(format_str.format(*headers))
    print('-' * (sum(column_widths) + 13) + '+')
    for i in data:
        print(format_str.format(*i))
    print('-' * (sum(column_widths) + 13) + '+')

def data_process(device_ip, device_info):
    filteredData = [(key, device_info[key]) for key in device_info if device_info[key] < args.e and device_info[key] > args.s]
    sortedData =  sorted(filteredData, key=lambda row: row[1], reverse=True)
    trancatedData = sortedData[:args.n]
    zone = get_zone(device_ip)
    rows = [("FIP_IN_" + i[0], i[0], zone, i[1], 0) for i in trancatedData]
    return rows

def parseArgs(parser):
    parser.add_argument('--cpu', help="choose the device ip to checked from multiple devices", default="all", type=str)
    parser.add_argument('--device', help="choose the device ip to checked from multiple devices", type=str)
    parser.add_argument('--username', help='device system username ,If not entered, '
                                           'search for the password in the /etc/neutron/fwaas.ini.'
                                           ' Note that if encrypted in the configuration file, the connection may fail', type=str)
    parser.add_argument('--device_pw', help='device system password ,If not entered, '
                                            'search for the password in the /etc/neutron/fwaas.ini.'
                                            ' Note that if encrypted in the configuration file, the connection may fail', type=str)
    parser.add_argument('--n', help="show top n devices info, default 30",default=30, type=int)
    parser.add_argument('--s', help="lower bound of session number, default 0",default=0, type=int)
    parser.add_argument('--e', help="upper bound of session number, default 99999999",default=99999999, type=int)
    args = parser.parse_args()
    print('--------------------------------------')
    print('device: %s' % args.device)
    print('username: %s' % args.username)
    print('device_pw: %s' % args.device_pw)
    print('cpu: %s' % args.cpu)
    print('number: %s' % args.n)
    print('lower bound: %s' % args.s)
    print('upper bound: %s' % args.e)
    print('--------------------------------------')
    if(not(args.device and args.username and args.device_pw)):
        print("device_ip/username/device_pw are necessary!")
        exit(0)
    
if __name__ == '__main__':
    os.system("clear")
    parser = argparse.ArgumentParser()
    parseArgs(parser)
    args = parser.parse_args()
    device = {
        "device_ip": args.device,
        "username": args.username,
        "password": args.device_pw
    }
    ph = PluginHost(443)
    get_device_cpu(device)
    device_info = get_device_info(device)
    formatOutput(device["device_ip"], device_info)