import pandas as pd
import logging
from colorama import Fore
from netmiko import ConnectHandler
from numpy.core.defchararray import strip

pd.set_option('display.max_columns', None)
pd.set_option('max_colwidth', None)
pd.set_option('max_seq_item', None)
pd.set_option('display.width', 1000)

data_2 = pd.read_excel(r'C:\Users\dev\Desktop\sample_rules\Sample Application rules - Azure Firewall.xlsx')
data = pd.read_excel(r'C:\Users\dev\Desktop\sample_rules\Sample Network rules - Azure Firewall[14].xlsx')
df = pd.DataFrame(data, columns=['Name', 'SourceAddresses', 'DestinationAddresses', 'ActionType', 'protocols',
                                 'DestinationPorts'])
df_2 = pd.DataFrame(data_2, columns=['Name', 'SourceAddresses', 'DestinationAddresses', 'ActionType', 'Protocol'])

logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
logger = logging.getLogger("netmiko")

fortigate = {
    'device_type': 'fortinet',
    'username': 'fgtuser',
    'password': 'T3st3d123$!!!',
    'host': '104.41.226.251',
    'session_log': 'netmiko_session.log',
    'global_delay_factor': 0.2,
    'fast_cli': False,
}
net_connect = ConnectHandler(**fortigate)
counter = 0
for i, j in df.iterrows():
    counter = counter + 1
    nameRule = df.loc[i, 'Name']
    sourceAddresses = df.loc[i, 'SourceAddresses']
    destinationAddresses = df.loc[i, 'DestinationAddresses']
    actionType = df.loc[i, 'ActionType']
    protocol = df.loc[i, 'protocols']
    destinationPorts = df.loc[i, 'DestinationPorts']
    print(Fore.RED + "********************************************")
    print(Fore.RED + "********* Network Rule Creation ************")
    print(Fore.LIGHTWHITE_EX + "Rule on AZURE-FortiGate will be created as below: ")
    print(Fore.LIGHTWHITE_EX + "Rule name: " + str(nameRule))
    print(Fore.LIGHTWHITE_EX + "Source Address: " + str(sourceAddresses))
    print(Fore.LIGHTWHITE_EX + "Destination Address: " + str(destinationAddresses))
    print(Fore.LIGHTWHITE_EX + "Action: " + str(actionType))
    print(Fore.LIGHTWHITE_EX + "Protocol enabled: " + str(protocol))
    print(Fore.LIGHTWHITE_EX + "Destination ports: " + str(destinationPorts))
    print(Fore.RED + "********************************************")

    # choosing the delimiter in our case -->,
    # splitting using split()
    delim = ","
    if str(sourceAddresses) == "":
        sourceAddresses = "ALL,"
        listsrcip = sourceAddresses.split(delim)
    if str(sourceAddresses) == "nan":
        sourceAddresses = "ALL,"
        listsrcip = sourceAddresses.split(delim)
    if str(destinationAddresses) == "":
        destinationAddresses = "ALL,"
        listdstip = destinationAddresses.split(delim)
    if str(destinationAddresses) == "nan":
        destinationAddresses = "ALL,"
        listdstip = destinationAddresses.split(delim)
    if "," not in str(sourceAddresses):
        sourceAddresses = str(sourceAddresses) + ","
        listsrcip = sourceAddresses.split(delim)
    if "," not in str(destinationAddresses):
        destinationAddresses = str(destinationAddresses) + ","
        listdstip = destinationAddresses.split(delim)

    listsrcip = sourceAddresses.split(delim)
    listdstip = destinationAddresses.split(delim)
    listprotocol = protocol.split(delim)
    listdestinationports = destinationPorts.split(delim)
    # generate an array with all the element inside, that I can query every object independently
    # one for the source addresses and the other for the destination addresses, ports and protocols
    arraysrcip = []
    arraydstip = []
    arrayprotocols = []
    arrayports = []
    # loop source addresses
    for dstip in listdstip:
        arraydstip.append(dstip)
        send_show_firewalldaddr = net_connect.send_command_timing("show firewall address " + str(dstip))
        # if the destination addresses firewall object is not found I will create it
        if send_show_firewalldaddr.__contains__("not found"):
            print(Fore.LIGHTGREEN_EX + "Object not found..creating.... dstIP --> " + str(dstip.strip()))
            send_command_config_fa = net_connect.send_command_timing("config firewall address")
            send_command_config_edit = net_connect.send_command_timing("edit " + str(dstip))
            # I would assume if in the cell the IP is without the / at the end it's a single host entry dstIP
            if "/" not in dstip != "ALL":
                send_command_config_setsubnet = net_connect.send_command_timing("set subnet " + str(dstip) + "/32")
                send_command_next = net_connect.send_command_timing("next")
                send_command_end = net_connect.send_command_timing("end")
            # If the cell is blank I would assume that the destination ip is ALL
            elif dstip == "ALL":
                send_command_config_setsubnet = net_connect.send_command_timing("set subnet " + "0.0.0.0/0")
                send_command_next = net_connect.send_command_timing("next")
                send_command_config_sety = net_connect.send_command_timing("y")
                send_command_end = net_connect.send_command_timing("end")
            # If the cell is blank I would assume that the destination ip is ALL
            elif dstip == "nan":
                send_command_config_setsubnet = net_connect.send_command_timing("set subnet " + "0.0.0.0/0")
                send_command_next = net_connect.send_command_timing("next")
                send_command_config_sety = net_connect.send_command_timing("y")
                send_command_end = net_connect.send_command_timing("end")
    # loop destination addresses
    for srcip in listsrcip:
        arraysrcip.append(srcip)
        send_show_firewallsaddr = net_connect.send_command_timing("show firewall address " + str(srcip))
        # if the source addresses firewall object is not found I will create it
        if send_show_firewallsaddr.__contains__("not found"):
            print(Fore.LIGHTGREEN_EX + "Object not found..creating.... srcIP --> " + str(srcip.strip()))
            send_command_config_fa = net_connect.send_command_timing("config firewall address")
            send_command_config_edit = net_connect.send_command_timing("edit " + str(srcip))
            # I would assume if in the cell the IP is without the / at the end it's a single host entry srcIP
            if "/" not in srcip != "ALL":
                send_command_config_setsubnet = net_connect.send_command_timing("set subnet " + str(srcip) + "/32")
                send_command_next = net_connect.send_command_timing("next")
                send_command_end = net_connect.send_command_timing("end")
            # If the cell is blank I would assume that the source ip is ALL
            elif srcip == "ALL":
                send_command_config_setsubnet = net_connect.send_command_timing("set subnet " + "0.0.0.0/0")
                send_command_next = net_connect.send_command_timing("next")
                send_command_config_sety = net_connect.send_command_timing("y")
                send_command_end = net_connect.send_command_timing("end")
            # If the cell is nan I would assume that the source ip is ALL
            elif srcip == "nan":
                send_command_config_setsubnet = net_connect.send_command_timing("set subnet " + "0.0.0.0/0")
                send_command_next = net_connect.send_command_timing("next")
                send_command_config_sety = net_connect.send_command_timing("y")
                send_command_end = net_connect.send_command_timing("end")
    # loop protocols and ports
    for proto in listprotocol:
        for ports in listdestinationports:
            arrayports.append(strip(proto))
            arrayprotocols.append(strip(ports))
            # ICMP protocol it's already present as ICMP_ALL
            if proto != 'ICMP':
                send_show_service = net_connect.send_command_timing("show firewall service custom " + str(strip(proto))
                                                                    + "-" + str(strip(ports)))
                # if the protocol-ports service object is not found I will create it
                if send_show_service.__contains__("not found"):
                    print("Object not found..creating.... proto-port --> " + str(strip(proto)) + "-" +
                          str(strip(ports)))
                    send_command_config_fs = net_connect.send_command_timing("config firewall service custom ")
                    send_command_config_edit = net_connect.send_command_timing("edit " + str(strip(proto)) + "-" +
                                                                               str(strip(ports)))
                    send_command_config_setproto = net_connect.send_command_timing("set protocol TCP/UDP/SCTP")
                    send_command_config_tcprange = net_connect.send_command_timing("set tcp-portrange " +
                                                                                   str(strip(ports)))
                    send_command_next = net_connect.send_command_timing("next")
                    send_command_end = net_connect.send_command_timing("end")

            send_command_config = net_connect.send_command_timing("config firewall policy")
            send_command_edit = net_connect.send_command_timing("edit 0")
            # delete the spurious white space inside the name of the rule
            nameRule_final = nameRule.replace(" ", "")
            send_command_name = net_connect.send_command_timing("set name " + str(nameRule_final))
            send_command_srcintf = net_connect.send_command_timing("set srcintf any")
            send_command_dstintf = net_connect.send_command_timing("set dstintf any")
            send_command_schedule = net_connect.send_command_timing("set schedule always")
            # delete the spurious comma inside the source addresses
            srcaddress_final = sourceAddresses.replace(",", " ")
            send_command_srcaddr = net_connect.send_command_timing("set srcaddr " + str(srcaddress_final))
            # delete the spurious comma inside the destination addresses
            dstaddress_final = destinationAddresses.replace(",", " ")
            send_command_dstaddr = net_connect.send_command_timing("set dstaddr " + str(dstaddress_final))
            if actionType.__contains__("Allow"):
                policyAction = "accept"
                send_command_action = net_connect.send_command_timing("set action " + str(policyAction))
            else:
                policyAction = "deny"
                send_command_action = net_connect.send_command_timing("set action " + str(policyAction))
            if str(protocol) == 'ICMP':
                protocol_all_icmp = 'ALL_ICMP'
                send_command_protocol = net_connect.send_command_timing("set service " + protocol_all_icmp)
                send_command_end = net_connect.send_command_timing("next")
                send_command_end = net_connect.send_command_timing("end")
            else:
                send_command_protocol = net_connect.send_command_timing("set service " + str(strip(proto))
                                                                        + "-" + str(strip(ports)))
                send_command_end = net_connect.send_command_timing("next")
                send_command_end = net_connect.send_command_timing("end")

for r, t in df_2.iterrows():
    counter = counter + 1
    nameRule = df_2.loc[r, 'Name']
    sourceAddresses = df_2.loc[r, 'SourceAddresses']
    destinationAddresses = df_2.loc[r, 'DestinationAddresses']
    actionType = df_2.loc[r, 'ActionType']
    protocol = df_2.loc[r, 'Protocol']
    print(Fore.RED + "********************************************")
    print(Fore.RED + "********* Application Rule Creation ************")
    print(Fore.LIGHTWHITE_EX + "Rule on AZURE-FortiGate will be created as below: ")
    print(Fore.LIGHTWHITE_EX + "Rule name: " + str(nameRule))
    print(Fore.LIGHTWHITE_EX + "Source Address: " + str(sourceAddresses))
    print(Fore.LIGHTWHITE_EX + "Destination Address: " + str(destinationAddresses))
    print(Fore.LIGHTWHITE_EX + "Action: " + str(actionType))
    print(Fore.LIGHTWHITE_EX + "Protocol and Destination ports are mixed together analizyng..." + protocol)
    print(Fore.RED + "********************************************")
    delim = " "
    listprotocol = protocol.split(delim)
    arraysrcip_app = []
    arraydstip_app = []
    arrayprotocols_app = []
    arrayports_app = []
    for proto in listprotocol:
        proto_ports_cleaned = proto.replace("_x000D_", "")
        round2 = proto_ports_cleaned
        proto_ports_cleaned_2 = round2.replace("{", "")
        round3 = proto_ports_cleaned_2
        proto_ports_cleaned_3 = round3.replace("[", "")
        round4 = proto_ports_cleaned_3
        proto_ports_cleaned_4 = round4.replace("]", "")
        round5 = proto_ports_cleaned_4
        proto_ports_cleaned_5 = round5.replace("}", "")
        arrayports_app.append(strip(proto_ports_cleaned_5))
        for i in arrayports_app:
            if i != " ":
                print(i)


