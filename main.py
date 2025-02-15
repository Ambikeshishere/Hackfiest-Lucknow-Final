import os

def show_menu():
    print("1. File Scanner")
    print("2. Network Traffic Analyzer")
    print("3. Phishing URL Detector")
    print("4. Process Monitor")
    print("5. System Information Service")
    print("6. Emails Checking")
    print("7. Exit")
    return input("Choose an option: ")

if __name__ == "__main__":
    while True:
        choice = show_menu()
        if choice == "1":
            os.system("python file_scanner.py")
        elif choice == "2":
            os.system("python network_analyzer.py")
        elif choice == "3":
            os.system("python Website_checker.py")
        elif choice == "4":
            os.system("python process_monitor.py")
        elif choice == "5":
            os.system("python service.py")
        elif choice == "6":
            os.system("python emails_checker.py")
        elif choice == "7":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
