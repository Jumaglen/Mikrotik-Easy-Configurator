# Author: Glen Juma
# Date: 2023-11-02

# Description: This python code uses a collection of user #inputs variables such as ip addresses and will automatically #interact with the router via ssh to set up the router.

# License:
# This code is released under the MIT License.
# See the LICENSE file or the "LICENSE" section in the project #repository for details.

import ipaddress
import paramiko
import getpass
import time


def establish_ssh_connection(router_ip, username, password):
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the MikroTik router
        ssh.connect(router_ip, username=username, password=password)
        
        return ssh
    
    except Exception as e:
        print(f"Failed to establish an SSH connection: {str(e)}")
        return None

def validate_ipv4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

def get_valid_input(prompt, validation_func):
    while True:
        value = input(prompt)
        if validation_func(value):
            return value
        else:
            print("Invalid input. Please try again.")

#function to calculate network address and ip pool range
def calculate_network_broadcast(lan_ip, lan_subnet):

    network = ipaddress.IPv4Network(f"{lan_ip}/{lan_subnet}", strict=False)
   # Get the network address
    lan_address = network.network_address

    # Get the first usable host address (network address + 1)
    lan_first_ip = lan_address + 10

    lan_gateway = lan_address + 1

    # Get the last usable host address (broadcast address - 1)
    last_usable_host = network.broadcast_address - 10

    pool_range = {lan_first_ip}-{last_usable_host}

    return lan_address, pool_range, lan_gateway



def configure_router(ssh, hostname, wan_ip, wan_subnet, wan_gateway, new_lan_no, lan_ip, pool_range, lan_ip_pool_name, wlan_interface_no, lan_subnet, bridge_name):
    try:
        #Set hostname
        print("Setting Hostname.")
        ssh.exec_command(f'/system identity set name={hostname}')
        time.sleep(2)
        #Set WAN interface
        print("Setting WAN IP Address")
        ssh.exec_command(f'/ip address add address={wan_ip}/{wan_subnet} interface=ether2')
        time.sleep(2)
        print("Setting WAN route")
        ssh.exec_command(f'/ip route add gateway={wan_gateway}')
        time.sleep(2)
        print("Setting LAN IP Pool")
        ssh.exec_command(f'/ip pool add name={lan_ip_pool_name} ranges={pool_range}') 
        # Create a bridge and add LAN interfaces
        time.sleep(2)
        print("Setting Bridge Interface")
        ssh.exec_command(f'/interface bridge add name={bridge_name}')
        time.sleep(2)
        print("Setting Bridge Interface IP Address")
        ssh.exec_command(f'/ip address add address={lan_ip}/{lan_subnet} interface={bridge_name}')
        time.sleep(2)
        for x in range(3, new_lan_no):
                print(f'Adding interface ether{x} to bridge port')
                try:
                    ssh.exec_command(f'/interface bridge port add interface=ether{x} bridge={bridge_name}')
                    time.sleep(2)
                except Exception as e:
                    print(f"Failed to add interface ether{x} to bridge: {str(e)}")
        if wlan_interface_no == 1:
            # TODO: Write code for single-band router
            pass
            print(f"Adding interface wlan1 to bridge port")
            try:
                ssh.exec_command(f'/interface bridge port add interface=wlan1 bridge={bridge_name}')
                time.sleep(2)
            except Exception as e:
                print(f"Failed to add interface wlan1 to bridge: {str(e)}")

        elif wlan_interface_no == 2:
            for yz in range(0, 3):
                print(f'Adding interface wlan{yz} to bridge port')
                try:
                    ssh.exec_command(f'/interface bridge port add interface=wlan{yz} bridge={bridge_name}')
                    time.sleep(2)
                except Exception as e:
                    print(f"Failed to add interface wlan1 to bridge: {str(e)}")
        time.sleep(2)
        print("Router configuration completed.")
    except Exception as e:
        print(f"Failed to configure the router: {str(e)}")

def configure_firewall(ssh):
    try:
        # Add firewall rules here
        # Example:
        ssh.exec_command('/ip firewall filter add chain=input action=accept protocol=tcp dst-port=22')
        time.sleep(2)
        ssh.exec_command('/ip firewall filter add chain=input connection-state=established,related action=accept comment="accept established,related')
        time.sleep(2)
        ssh.exec_command('/ip firewall filter add chain=input in-interface=ether1 protocol=icmp action=accept comment="allow ICMP')
        time.sleep(2)
        ssh.exec_command('/ip firewall filter add chain=input in-interface=ether1 protocol=tcp port=8291 action=accept comment="allow Winbox')
        time.sleep(2)
        ssh.exec_command('/ip firewall filter add chain=input in-interface=ether1 protocol=tcp port=22 action=accept comment="allow SSH')
        time.sleep(2)
        ssh.exec_command('/ip firewall filter add chain=input connection-state=invalid action=drop')
        time.sleep(2)
        ssh.exec_command('/ip firewall filter add chain=input in-interface=ether1 action=drop comment="block everything else')
        time.sleep(2)
        ssh.exec_command('/ip service disable telnet,ftp,api')
        time.sleep(2)
        ssh.exec_command('/ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade')
        time.sleep(2)
        print("Firewall configuration completed.")
    
    except Exception as e:
        print(f"Failed to configure the firewall: {str(e)}")

def configure_wifi(ssh, wifi_name, wlan_interface_no, wifi_password):
    try:
        
        if wlan_interface_no == 1:
            # Configure 2.4GHz wireless settings
            ssh.exec_command(f'/interface wireless set wlan1 band=2ghz-b/g/n channel-width=20/40mhz-Ce distance=indoors mode=ap-bridge ssid={wifi_name} wireless-protocol=802.11 security-profile={wifi_name} frequency-mode=regulatory-domain country=kenya')
            time.sleep(2)
            ssh.exec_command(f'/interface wireless security-profiles add name={wifi_name} authentication-types=wpa2-psk mode=dynamic-keys wpa2-pre-shared-key={wifi_password}')
            time.sleep(2)
        else:
            # Configure 2.4GHz/5GHz wireless settings
            ssh.exec_command(f'/interface wireless set wlan1 band=2ghz-b/g/n channel-width=20/40mhz-Ce distance=indoors mode=ap-bridge ssid={wifi_name} wireless-protocol=802.11 security-profile={wifi_name} frequency-mode=regulatory-domain country=kenya')
            time.sleep(2)
            ssh.exec_command(f'/interface wireless security-profiles add name={wifi_name} authentication-types=wpa2-psk mode=dynamic-keys wpa2-pre-shared-key={wifi_password}')
            time.sleep(2)

            wifi_5_name = input("Enter the 5GHz Wi-Fi SSID: ")
            wifi_5_password = input("Enter the 5GHz Wi-Fi password: ")
            ssh.exec_command(f'/interface wireless set wlan2 band=5ghz-a/n/ac channel-width=20/40/80mhz-XXXX distance=indoors mode=ap-bridge ssid={wifi_5_name} wireless-protocol=802.11 security-profile={wifi_5_name} frequency-mode=regulatory-domain country=kenya')
            time.sleep(2)
            ssh.exec_command(f'/interface wireless security-profiles add name={wifi_5_name} authentication-types=wpa2-psk mode=dynamic-keys wpa2-pre-shared-key={wifi_5_password}')
            time.sleep(2)
            print("Wi-Fi configuration completed.")

    except Exception as e:
        print(f"Failed to configure Wi-Fi: {str(e)}")

def configure_dhcp_server(ssh, dhcp_pool_name, bridge_name, lan_ip_pool_name, lan_gateway, lan_address, lan_subnet):
    try:
        # Configure the DHCP server
        time.sleep(2)
        print("Setting DHCP Server")
        ssh.exec_command(f'/ip dhcp-server add name={dhcp_pool_name} interface={bridge_name} address-pool={lan_ip_pool_name} disabled=no')
        time.sleep(2)
        print("Setting DHCP Server ip addresses")
        ssh.exec_command(f'/ip dhcp-server network add address={lan_address}/{lan_subnet} netmask={lan_subnet} gateway={lan_gateway} dns-server=8.8.8.8')
        time.sleep(2)
        print("DHCP server and IP pool configuration completed.")
        time.sleep(3)
    except Exception as e:
        print(f"Failed to configure DHCP server: {str(e)}")
            
def main():
    #User defined values



    #SSH log in inputs
    router_ip = get_valid_input("Enter router ip address: ", validate_ipv4)

    username = input("Enter the SSH username: ")

    password = getpass.getpass("Enter the SSH password: ")   

    #Router Settings
    hostname = input("Enter the hostname of the MikroTik device: ") 

    wan_ip = get_valid_input("Enter the WAN IP address: ", validate_ipv4)

    wan_subnet = int(input("Enter the WAN subnet mask: e.g 24 "))

    wan_gateway = get_valid_input("Enter the WAN Gateway IP address: ", validate_ipv4) 

    lan_ip = get_valid_input("Enter the LAN IP address: ", validate_ipv4)

    lan_subnet =  int(input("Enter the LAN subnet mask: e.g 24 "))

    lan_ip_pool_name = ("defaultPool")

    lan_interface_no = int(input("Enter the Number of lan ports on the Mikrorik router: "))

    new_lan_no = lan_interface_no + 1

    lan_address, pool_range, lan_gateway = calculate_network_broadcast(lan_ip,lan_subnet) 

    bridge_name = "defaultBridge"

    dhcp_pool_name = "defaultPool"   

    wlan_interface_no = input("Enter 2 for dual band router or 1 for single band")

    wifi_name = input("Enter the 2.4Ghz Wi-Fi SSID: ")

    wifi_password = input("Enter the 2.4Ghz Wi-Fi password: ")
    
    ssh = establish_ssh_connection(router_ip, username, password)
    
    if ssh:
        configure_router(ssh, hostname, wan_ip, wan_subnet, wan_gateway, new_lan_no, lan_ip, pool_range, lan_ip_pool_name, wlan_interface_no, lan_subnet, bridge_name)
        configure_firewall(ssh)
        configure_wifi(ssh, wifi_name, wlan_interface_no, wifi_password)
        configure_dhcp_server(ssh, dhcp_pool_name, bridge_name, lan_ip_pool_name, lan_gateway, lan_address, lan_subnet)
        ssh.close()

if __name__ == "__main__":
    main()
