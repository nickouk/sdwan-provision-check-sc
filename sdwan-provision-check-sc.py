import requests
import urllib3
import getpass
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
except ImportError:
    print("FATAL: netmiko is not installed. Please run 'pip install netmiko' in your virtual environment.")
    sys.exit(1)

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_vmanage_session(vmanage_ip, username, password):
    """
    Authenticate to vManage and return a session object.
    """
    session = requests.Session()
    session.verify = False 
    
    login_url = f"https://{vmanage_ip}/j_security_check"
    login_data = {'j_username': username, 'j_password': password}
    
    try:
        response = session.post(login_url, data=login_data, timeout=10)
        response.raise_for_status()
        
        # If the response contains an HTML login page, it means authentication failed
        if '<html>' in response.text.lower():
            print("Authentication to vManage failed. Please check your credentials.")
            sys.exit(1)
            
        print("Successfully authenticated to vManage.\n")
        return session
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to vManage: {e}")
        sys.exit(1)


def get_ios_xe_devices(session, vmanage_ip):
    """
    Retrieve and return a list of IOS-XE hostnames and System IPs.
    """
    device_url = f"https://{vmanage_ip}/dataservice/device"
    
    try:
        response = session.get(device_url, timeout=10)
        response.raise_for_status()
        
        devices = response.json().get('data', [])
        target_devices = []
        
        for device in devices:
            # Check for edge devices
            if device.get('personality') == 'vedge':
                device_type = device.get('device-type', '').lower()
                device_os = device.get('device-os', '').lower()
                
                # Check for ios-xe in device-os or cEdge type
                is_ios_xe = (
                    device_os == 'ios-xe' or 
                    device_os == 'next' or
                    'isr' in device_type or 
                    'asr' in device_type or 
                    'c8' in device_type or
                    'cedge' in device_type or
                    device_type == 'vedge'
                )
                
                if is_ios_xe:
                    hostname = device.get('host-name', 'Unknown')
                    system_ip = device.get('system-ip', 'Unknown')
                    target_devices.append((hostname, system_ip))
                    
        return target_devices
            
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving devices from vManage: {e}")
        return []
    except ValueError:
        print("Failed to parse the response as JSON.")
        return []


def check_switchports(hostname, ip, username, password):
    """
    SSH into the device and check G0/1/0 and G0/1/1 switchport statuses.
    """
    device = {
        'device_type': 'cisco_ios',
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 10,
        'global_delay_factor': 0.5
    }
    
    result = {
        "hostname": hostname,
        "ip": ip,
        "status": "unreachable",
        "flagged": False,
    }
    
    try:
        with ConnectHandler(**device) as net_connect:
            # 1. G0/1/0 checks (Trunk and UP)
            run_g010 = net_connect.send_command("show run interface GigabitEthernet0/1/0")
            is_trunk = "switchport mode trunk" in run_g010.lower()
            
            sh_g010 = net_connect.send_command("show interface GigabitEthernet0/1/0")
            g010_up = "is up, line protocol is up" in sh_g010.lower()
            
            # 2. G0/1/1 checks (Not administratively down)
            sh_g011 = net_connect.send_command("show interface GigabitEthernet0/1/1")
            g011_not_disabled = False
            
            # Ensure the interface exists and hasn't thrown an invalid input error
            if "invalid input" not in sh_g011.lower() and "invalid interface" not in sh_g011.lower():
                # Checking if it's NOT disabled (i.e. not admin down)
                if "administratively down" not in sh_g011.lower():
                    g011_not_disabled = True
            
            # Flag it if conditions match
            if is_trunk and g010_up and g011_not_disabled:
                result["flagged"] = True
                
            result["status"] = "success"
                
    except NetMikoAuthenticationException:
        result["status"] = "auth_error"
    except Exception as e:
        result["status"] = "unreachable"
        
    return result


def main():
    print("=== SD-WAN Switchport Provisioning Checker ===")
    
    # Prompt for credentials
    vmanage_user = input("vManage username: ")
    vmanage_pass = getpass.getpass("vManage password: ")
    ise_user = input("ISE username: ")
    ise_pass = getpass.getpass("ISE password: ")
    
    # Target vManage
    vmanage_hostname = "vmanage-953677893.sdwan.cisco.com"
    
    print(f"\nAuthenticating with {vmanage_hostname}...")
    session = get_vmanage_session(vmanage_hostname, vmanage_user, vmanage_pass)
    
    print("Retrieving IOS-XE device list...")
    target_devices = get_ios_xe_devices(session, vmanage_hostname)
    
    print("Closing vManage session...")
    session.close()
    
    if not target_devices:
        print("No IOS-XE devices found.")
        sys.exit(0)
        
    print(f"\nInitiating parallel SSH connections to {len(target_devices)} devices...")
    
    failed_devices = []
    flagged_devices = []
    
    # Multithreading SSH connections for speed
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for hostname, ip in target_devices:
            if ip == 'Unknown':
                failed_devices.append((hostname, ip, "Invalid/Unknown IP Address"))
            else:
                futures.append(executor.submit(check_switchports, hostname, ip, ise_user, ise_pass))
        
        for future in as_completed(futures):
            res = future.result()
            hostname = res["hostname"]
            ip = res["ip"]
            status = res["status"]
            flagged = res["flagged"]
            
            print(f"[{hostname} ({ip})] ", end="")
            if status == "success":
                if flagged:
                    print("Status: FLAGGED (G0/1/0 is Trunk & Up, G0/1/1 is not disabled)")
                    flagged_devices.append((hostname, ip))
                else:
                    print("Status: OK")
            elif status == "auth_error":
                print("Authentication error.")
                failed_devices.append((hostname, ip, "Authentication Error"))
            elif status == "unreachable":
                print("Unreachable / Connection Timeout.")
                failed_devices.append((hostname, ip, "Unreachable or Timeout"))
                
    print("\n" + "="*60)
    print("=== PROVISIONING CHECK REPORT ===")
    print("="*60)
    
    print("\n--- FLAGGED DEVICES ---")
    print("(G0/1/0 is a Trunk & Up AND G0/1/1 is not disabled)")
    if flagged_devices:
        for host, ip in flagged_devices:
            print(f"- {host} ({ip})")
    else:
        print("No devices were flagged based on the criteria.")
        
    print("\n--- DEVICES WITH CONNECTION ERRORS ---")
    if failed_devices:
        for host, ip, reason in failed_devices:
            print(f"- {host} ({ip}) : {reason}")
    else:
        print("All devices were successfully contacted.")

    print("\nCheck Complete.")

if __name__ == "__main__":
    main()
