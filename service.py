import psutil
import socket
import requests
import os
import platform
import datetime
from screeninfo import get_monitors
import subprocess

def get_local_ip():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return None

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org")
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error getting public IP: {e}")
        return None

def get_network_status():
    try:
        interfaces = psutil.net_if_addrs()
        network_info = {}
        for interface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    network_info[interface] = addr.address
        return network_info
    except Exception as e:
        print(f"Error getting network status: {e}")
        return None

def get_ram_consumption():
    try:
        memory_info = psutil.virtual_memory()
        return memory_info.percent, memory_info.used, memory_info.available
    except Exception as e:
        print(f"Error getting RAM consumption: {e}")
        return None

def get_cpu_performance():
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        cpu_per_core = psutil.cpu_percent(interval=1, percpu=True)
        return cpu_usage, cpu_per_core
    except Exception as e:
        print(f"Error getting CPU performance: {e}")
        return None, None

def get_os_time():
    try:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return current_time
    except Exception as e:
        print(f"Error getting OS time: {e}")
        return None

def get_location():
    try:
        ip = get_public_ip()
        if ip:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            location_data = response.json()
            city = location_data.get("city", "Unknown")
            country = location_data.get("country", "Unknown")
            return f"{city}, {country}"
        return "Unknown Location"
    except Exception as e:
        print(f"Error getting location: {e}")
        return "Unknown Location"

def get_admin_name():
    try:
        if platform.system() == "Windows":
            user = os.getlogin()
            return user
        elif platform.system() in ["Linux", "Darwin"]:
            user = os.getlogin()
            return user
        return "Unknown User"
    except Exception as e:
        print(f"Error getting admin name: {e}")
        return None

def get_connected_devices():
    try:
        monitors = get_monitors()
        connected_monitors = [monitor.name for monitor in monitors]
        input_devices = psutil.disk_partitions()
        return connected_monitors, input_devices
    except Exception as e:
        print(f"Error getting input/output devices: {e}")
        return [], []

def get_gpu_info():
    try:
        if platform.system() == "Windows":
            gpu_info = subprocess.check_output("wmic path win32_videocontroller get caption", shell=True)
            gpu_info = gpu_info.decode().strip().split("\n")[1]
            return gpu_info
        elif platform.system() == "Linux":
            gpu_info = subprocess.check_output("lspci | grep VGA", shell=True)
            gpu_info = gpu_info.decode().strip().split("\n")[0]
            return gpu_info
        elif platform.system() == "Darwin":
            gpu_info = subprocess.check_output("system_profiler SPDisplaysDataType", shell=True)
            gpu_info = gpu_info.decode().strip().split("\n")
            for line in gpu_info:
                if "Chipset Model" in line:
                    return line.strip().split(":")[1].strip()
            return "Unknown GPU"
        return "Unknown GPU"
    except Exception as e:
        print(f"Error getting GPU information: {e}")
        return "Unknown GPU"

def display_system_info():
    print("Fetching system information...\n")

    local_ip = get_local_ip()
    public_ip = get_public_ip()
    network_info = get_network_status()

    print("Network Information:")
    print(f"Local IP Address: {local_ip}")
    print(f"Public IP Address: {public_ip}")
    print(f"Network Interfaces: {network_info}\n")

    ram_usage_percent, ram_used, ram_available = get_ram_consumption()
    print("Current RAM Consumption:")
    print(f"RAM Usage: {ram_usage_percent}%")
    print(f"Used RAM: {ram_used / (1024 ** 3):.2f} GB")
    print(f"Available RAM: {ram_available / (1024 ** 3):.2f} GB\n")

    cpu_usage, cpu_per_core = get_cpu_performance()
    print(f"Total CPU Usage: {cpu_usage}%")
    print(f"Per-Core CPU Usage: {cpu_per_core}\n")

    os_time = get_os_time()
    print(f"Current OS Time: {os_time}\n")

    location = get_location()
    print(f"Location (Approximate): {location}\n")

    monitors, input_devices = get_connected_devices()
    print("Connected Devices:")
    print(f"Connected Monitors: {monitors}")
    print(f"Connected Input Devices: {input_devices}\n")

    gpu_info = get_gpu_info()
    print(f"GPU Information: {gpu_info}\n")

    admin_name = get_admin_name()

    print("\nAdministrator Information:")
    print(f"Administrator Name: {admin_name}")

if __name__ == "__main__":
    display_system_info()
