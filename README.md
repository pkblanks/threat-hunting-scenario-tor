# Official [Cyber Range](https://github.com/pkblanks) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/pkblanks/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the had the string “tor” in it and discovered what looks to be the user “employee_pb” downloaded a “tor” installer, did something that resulted in many TOR-related files being copied to the desktop and creation of a file called `tor-shopping-list.txt` on the desktop at 
`Jul 14, 2025 3:08:13 PM`.
These events began at `2025-07-20T17:10:27.0944072Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "paa-threat-hunt"
| where InitiatingProcessAccountName == "employee_pb"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-20T17:10:27.0944072Z) // all file events after tor browser was executed 
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/pkblanks/threat_hunt_files/blob/main/1.DeviceFileEvents.jpg">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-14.5.4.exe`. Based on the logs returned, at `1:15 PM on July 20, 2025`, an employee with username employee_pb on the computer paa-threat-hunt device ran the file `tor-browser-windows-x86_64-portable-14.5.4.exe` from their Downloads folder, using the command with a `/s` argument that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents // To determine if anything was executed or not 
| where DeviceName == "paa-threat-hunt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe" 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine , SHA256 // choosing the columns that works well with my search 
```
<img width="1212" alt="image" src="https://github.com/pkblanks/threat_hunt_files/blob/main/2.%20DeviceProcessEvent.jpg">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user “employee_pb” actually opened the tor browser for additional evidence/ confirmation. There was evidence that they did open it on `Jul 20, 2025 1:34:10 PM`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "paa-threat-hunt"
| where FileName has_any ("tor.exe", "tor-browser.exe", "firefox.exe") // Searches for activity involving the Tor browser/Firefox executables
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine , SHA256
| order by Timestamp desc 
```
<img width="1212" alt="image" src="https://github.com/pkblanks/threat_hunt_files/blob/main/3.%20DeviceProcess-opened%20tor%20browser.jpg">

---

### 4a. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

Searched for any indication the TOR browser was used to establish a connection using any of the known tor ports. At `1:41 PM on July 20, 2025`, the user employee_pb, an employee on the device paa-threat-hunt used `tor.exe` from the folder path `c:\users\employee_pb\desktop\tor browser\browser\torbrowser\tor\tor.exe` to successfully connect to a hidden TOR site at `https://www.ymmpxjo3jy7jgcmink.com`, using IP `149.56.45.200` on port `9001`, indicating anonymized browsing or potential access to the dark web. There were a few other connections as well.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "paa-threat-hunt"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001","9030", "9040","9050", 9051, 9150) // Ports used by tor browser
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/pkblanks/threat_hunt_files/blob/main/4.%20DeviceNetworks-tor_ports_accessed.jpg">

---
### 4b. Searched the DeviceNetworkEvents Table for TOR Network Connections over Common Web Ports

Multiple connections were identified over ports 80 and 443, indicating that the TOR Browser was used to access external websites via standard HTTP/HTTPS protocols, likely to bypass detection or conceal browsing activity.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "paa-threat-hunt"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ( 80, 443) // Other ports not tor ports
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/pkblanks/threat_hunt_files/blob/main/4b.%20DeviceNetworks-other_ports_accessed.jpg">

---

## 🕒 Chronological Event Timeline: TOR Activity by User employee_pb

### 1. Initial TOR Download and File Activity

- **Timestamp:** `Jul 14, 2025 @ 3:08 PM`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** ` C:\Users\employee_pb\Desktop\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 2. Process Execution - TOR Browser Silent Installation 

- **Timestamp:** `Jul 20, 2025 @ 1:15 PM`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe /S`
- **File Path:** `C:\Users\employee_pb\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Jul 20, 2025 @ 1:16–1:17 PM`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `Jul 20, 2025 @ 1:28 PM`
- **Event:** A network connection to IP `149.56.45.200` on port `9001` by user "employee_pb" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `Jul 20, 2025 @ 1:28` - Connected to `107.155.81.178` on port `443`.
  - `Jul 20, 2025 @ 1:28` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `Jul 20, 2025 @ 1:53–1:55 PM`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `paa-threat-hunt` by the user `employee_pb`. The device was isolated, and the user's direct manager was notified.

---
