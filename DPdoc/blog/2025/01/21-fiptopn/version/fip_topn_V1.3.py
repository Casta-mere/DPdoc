import time
import re
import pymysql
import paramiko
import os
import ConfigParser
import argparse
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from sqlalchemy import create_engine

try:
    import pycurl  # noqa
except ImportError:  # pragma: no cover
    pycurl = Curl = METH_TO_CURL = None  # noqa
else:
    from pycurl import Curl  # noqa

    METH_TO_CURL = {  # noqa
        "GET": pycurl.HTTPGET,
        "POST": pycurl.POST,
        "PUT": pycurl.UPLOAD,
        "HEAD": pycurl.NOBODY,
    }

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

            print(self.ip + 'connect success')
        except Exception as e:
            print(e)
            self.connect = False
            print(self.ip + 'connect fail')
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

class DbInfo(object):
    def __init__(self):
        self.get_db_conf()

    def get_db_conf(self):
        path_file = "/etc/neutron/neutron.conf"
        cp = ConfigParser.ConfigParser()
        cp.read(path_file)
        r = cp.get("database", 'connection')
        str2 = r.split('/')[2].replace(':', '@').split('@')
        return str2

class PluginHost(object):

    def __init__(self, device_port):
        self.configurations = {}
        self.host_name = self.get_host_name()
        self.get_plugin_conf(device_port)

    def get_plugin_conf(self, device_port):

        fwaas_conf = '/etc/neutron/fwaas_driver.ini'
        conf = ConfigParser.ConfigParser()
        conf.read(fwaas_conf)
        sections = conf.sections()
        external_sect_head = 'external_'
        external_sect_head2 = 'dptechnology'
        external_sects = [se for se in sections if se.startswith(external_sect_head) or se.startswith(external_sect_head2)]
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

    def get_db_conf(self):
        pass

class Mysql_Nat1to1(object):
    
    def __init__(self, my_ip="", my_name="", my_password="", my_mysql=""):
        self.my_ip = my_ip
        self.my_name = my_name
        self.my_password = my_password
        self.my_mysql = my_mysql

    def read_mysql(self):
        db = pymysql.connect(self.my_ip, self.my_name, self.my_password, self.my_mysql, charset="utf8")
        cursor = db.cursor()
        cursor.execute('select * from dptech_dummy_ip_allocations;')
        allocations_list_info = cursor.fetchall()
        cursor.execute('select * from floatingips;')
        floatingip_list_info = cursor.fetchall()
        db.close()
        return allocations_list_info, floatingip_list_info

def read_ini():
    """
    Read configuration from ini file.
    :param filename: filename of the ini file
    """

    config = ConfigParser.ConfigParser()
    if not os.path.exists("/etc/neutron/fwaas_driver.ini"):
        print("file not exist")
    config.read("/etc/neutron/fwaas_driver.ini")
    return config

def get_device_info(fw_info, num="all", device_pw=""):
    device_info = {}
    for i in fw_info.values():
        #if num != "all" and i['device_ip'] != num :
        #    continue
        if device_pw:
            ssh_dp = SSH_dp(i['device_ip'], 22, i['username'], i['password'])
        else:
            ssh_dp = SSH_dp(i['device_ip'], 22, i['username'], device_pw)
        if ssh_dp.connect == False:
            continue
        return_cmd = ssh_dp.excute_cmd("show version")
        box_cmd =  ssh_dp.excute_cmd("show session topn src-ip 50")
        box_cmd1 =  ssh_dp.excute_cmd("show session topn dst-ip 50")
        ans = box_cmd + "\n" + box_cmd1
        if("% Unknown command" in ans):
            matches = re.findall(r'\[SLOT\s+(\d+)\]', str(return_cmd))
            slot_numbers = matches
            result = {}
            for j in slot_numbers:
                return_cmd = ssh_dp.excute_cmd("show session topn slot %s src-ip 50" %(j))
                return_cmd1 = ssh_dp.excute_cmd("show session topn slot %s dst-ip 50" %(j))
                text = return_cmd + "\n" + return_cmd1

                ip_pattern = r"IP Address:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                session_pattern = r"Session Number:(\d+)"
                ip_addresses = re.findall(ip_pattern, text)
                session_numbers = re.findall(session_pattern, text)

                for ip, session in zip(ip_addresses, session_numbers):
                    if ip in result:
                        result[ip] += int(session)
                    else:
                        result[ip] = int(session)
        else:
            ip_pattern = r"IP Address:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            session_pattern = r"Session Number:(\d+)"

            ip_addresses = re.findall(ip_pattern, ans)
            session_numbers = re.findall(session_pattern, ans)
            result = {}
            for ip, session in zip(ip_addresses, session_numbers):
                if ip in result:
                    result[ip] += int(session)
                else:
                    result[ip] = int(session)
        ssh_dp.close()
        device_info[i['device_ip']] = result
    return device_info

def get_device_cpu(fw_info, device_pw=""):
    with open('/var/lib/neutron/cpu.txt', 'w') as file:
        file.write("cpu" +str(args.cpu) +" session!!!!!!!!!!!!!!!! 10 times")
    print(ph.configurations[fw_info])

    ssh_dp = SSH_dp(fw_info, 22, ph.configurations[fw_info]["username"], device_pw)
    if args.device:
        for i in range(10):
            if args.device == "all":
                ssh_dp.excute_cmd("sniffer filter all")
                return_cmd1 = ssh_dp.excute_cmd("sniffer capture session")
                with open('/var/lib/neutron/cpu.txt', 'a') as file:
                    file.write(return_cmd1)
            else:
                cmdd = "sniffer filter vcpu " + args.cpu
                ssh_dp.excute_cmd(cmdd)
                return_cmd1 = ssh_dp.excute_cmd("sniffer capture session")
                with open('/var/lib/neutron/cpu.txt', 'a') as file:
                    file.write(return_cmd1)
        return return_cmd1

def connect_db(password, device, device_pw, edge, number, lower, upper):
    db_info = ""
    for line in open("/etc/neutron/neutron.conf", "r"):
        if 'connection' in line:
            db_info = line.split(" ")[1]

    config = read_ini()
    fw_info = {}
    for section in config.sections():
        az = ""
        flag = False
        for k, v in config.items(section):
            if 'az' == k:
                fw_info[v] = {}
                az = v
                flag = True
            if(flag):
                if 'device_ip' == k:
                    fw_info[az][k] = v
                if 'username' == k:
                    fw_info[az][k] = v
                if 'password' == k:
                    fw_info[az][k] = v

    start_index = db_info.find("neutron:") + 8
    end_index = db_info.find("@", start_index)
    if start_index != -1 and end_index != -1 and password :
        new_connection = db_info[:start_index] + password + db_info[end_index:]
    else:
        new_connection = db_info
    engine = create_engine(new_connection)
    Session = sessionmaker(bind=engine)
    session = Session()
    results = session.execute(text("SELECT * FROM dptech_dummy_ip_allocations;")).fetchall()
    headers = ["policy_name","dummy_ip","zone","session","speed","type","port_id"]
    devices_info = []
    device_session = get_device_info(fw_info,device,device_pw)

    print("device_session", device_session)
    
    count = 0

    for i in results:
        try: 
            changdu = 0
            pianyi = 0
            device_info = ["","","","","","","" ]
            device_info[0] = "FIP_IN_"+i[1] # id
            device_info[1] = i[1]           # ip
            
            device_info[5] = i[4]           # type
            device_info[6] = i[3][:36]      # id
            zone = ""
            if device_info[5] == 'router':
                sqll = "SELECT * FROM routers WHERE id = :id"
                result = session.execute(text(sqll), {"id": device_info[6]}).fetchall()
                sqll = "SELECT * FROM router_az_bind WHERE router_id = :id"
                result = session.execute(text(sqll), {"id": device_info[6]}).fetchall()
                zone = result[0][1]
            elif device_info[5] == 'vm':
                sqll = "SELECT * FROM ports WHERE id = :id"
                result = session.execute(text(sqll), {"id": device_info[6]}).fetchall()
                sqll = "SELECT * FROM networks WHERE id = :id"
                result = session.execute(text(sqll), {"id": result[0][3]}).fetchall()
                zone = result[0][7]
                if len(zone) > 4:
                    zone = result[0][7][2:-2]
                else:
                    zone = ""
            elif device_info[5] == 'nat':
                sqll = "SELECT * FROM dptech_nat_gateways WHERE id = :id"
                result = session.execute(text(sqll), {"id": device_info[6]}).fetchall()
                sqll = "SELECT * FROM router_az_bind WHERE router_id = :id"
                result = session.execute(text(sqll), {"id": result[0][5]}).fetchall()
                zone = result[0][1]
            elif device_info[5] == 'sslvpn':
                sqll = "SELECT * FROM sslvpn_services WHERE id = :id"
                result = session.execute(text(sqll), {"id": device_info[6]}).fetchall()
                sqll = "SELECT * FROM router_az_bind WHERE router_id = :id"
                result = session.execute(text(sqll), {"id": result[0][-1]}).fetchall()
                zone = result[0][1]
            elif device_info[5] == 'ipsecvpn':
                sqll = "SELECT * FROM vpnservices WHERE id = :id"
                result = session.execute(text(sqll), {"id": device_info[6]}).fetchall()
                sqll = "SELECT * FROM router_az_bind WHERE router_id = :id"
                result = session.execute(text(sqll), {"id": result[0][7]}).fetchall()
                zone = result[0][1]
        except Exception as e:
            # print(e)
            continue
        
        try:
            device_ip =  device_info[1]
            sessions = device_session[device_session.keys()[0]]
            if device_ip and device_ip in sessions.keys():
                changdu = sessions[device_ip]
            device_info[2] = zone
            device_info[3] = changdu
            device_info[4] = pianyi

            if(device_info[2] != edge):
                continue
            if(device_info[3] < lower or device_info[3] > upper):
                continue
            devices_info.append(device_info)
            count += 1 
            if(count >= number):
                break
        except Exception as e:
            # print(e)
            pass

    sorted_rows = sorted(devices_info, key=lambda row: row[3], reverse=True)
    column_widths = [max(len(str(item)) for item in column) for column in zip(headers, *sorted_rows)]

    format_str = ' | '.join('{{{0}:<{1}}}'.format(i, width) for i, width in enumerate(column_widths))
    # os.system("clear")
    print('-' * (sum(column_widths) + 20) + '+')
    print(format_str.format(*headers))
    print('-' * (sum(column_widths) + 20) + '+')

    for i in sorted_rows:
        print(format_str.format(*i))
    print('-' * (sum(column_widths) + 20) + '+')
    return session

if __name__ == '__main__':
    ph = PluginHost(443)

    # args
    parser = argparse.ArgumentParser()
    parser.add_argument('--cpu', help="choose the device ip to checked from multiple devices",
                    type=str)
    parser.add_argument('--device', help="choose the device ip to checked from multiple devices",
                        default="all", type=str)
    parser.add_argument('--device_pw', help='device database password ,If not entered, '
                                           'search for the password in the /etc/neutron/fwaas.ini.'
                                           ' Note that if encrypted in the configuration file, the connection may fail',default='', type=str)
    parser.add_argument('--neutron_pw', help='neutron mysql database password ,If not entered, '
                                           'search for the password in the /etc/neutron/neutron.conf.'
                                           ' Note that if encrypted in the configuration file, the connection may fail',
                        default='', type=str)
    
    parser.add_argument('--n', help="show top n devices info",default=20, type=int)
    parser.add_argument('--s', help="lower bound of session number",default=1000, type=int)
    parser.add_argument('--e', help="upper bound of session number",default=99999999, type=int)
    args = parser.parse_args()
    print('device: %s' % args.device)
    print('neutron_pw: %s' % args.neutron_pw)
    print('device_pw: %s' % args.device_pw)
    print('number: %s' % args.n)
    print('lower bound: %s' % args.s)
    print('upper bound: %s' % args.e)

    if(args.s > args.e):
        print("Error! lower bound should be less than upper bound")

    if args.cpu:
        print(get_device_cpu(args.device, args.device_pw))
   
    print(ph.configurations) 
    #if args.device != 'all' and args.device not in ph.configurations:
     #   raise ValueError('device %s not in fwaas_driver.ini' % args.device)

    dbinfo = DbInfo().get_db_conf()
    database_password = dbinfo[1]
    if args.neutron_pw:
        database_password = args.neutron_pw
    my_mysql = Mysql_Nat1to1(my_ip=dbinfo[2], my_name=dbinfo[0], my_password=database_password, my_mysql="neutron")

    list1, list2 = my_mysql.read_mysql()

    if args.device == 'all':
        devise_list = list(ph.configurations.keys())
    else:
        devise_list = [args.device]

    dbinfo = DbInfo().get_db_conf()
    database_password = dbinfo[1]
    if args.neutron_pw:
        database_password = args.neutron_pw
        
    connect_db(args.neutron_pw,args.device,args.device_pw, ph.configurations[args.device]["zone"],args.n,args.s,args.e)
