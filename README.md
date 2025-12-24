# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Executive Summary
Using Microsoft Defender for Endpoint advanced hunting telemetry, including process execution, file system activity, and network connections, this investigation identified a silent installation, Tor-related artifacts on disk, and outbound traffic consistent with Tor network usage. This investigation demonstrates how endpoint logs can be leveraged to detect anonymization tools and support security policy enforcement and incident response.


## Steps the "Bad Actor" Took (Log & IoC Generation)
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse several onion sites (examples used for lab simulation):
   - Current Dread Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion```
   - Dark Markets Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```https://elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```
   - ** It's possible the onion link for Dread Forum has changed, for latest links, you can try to check here: https://dread-forum.com/ **
5. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
6.  Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// TOR Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine has "tor-browser-windows-x86_64-portable"
| where ProcessCommandLine has "/S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
// TOR Browser or service was successfully installed and is present on the disk
// User shopping list was created and, changed, or deleted
DeviceFileEvents
| order by TimeGenerated desc 
| where FileName has "tor" or FolderPath has "Tor Browser"
| project TimeGenerated, ActionType, DeviceName, FileName 

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe")
| where RemoteIP != "127.0.0.1"
| where RemotePort in (9001, 9030) or RemotePort > 1024
| project TimeGenerated, ActionType, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by TimeGenerated desc
```
## Defensive Interpretation
- TOR Browser was installed silently without user interaction.
- TOR binaries were executed from a non-standard, user-accessible directory.
- Network connections consistent with TOR relay activity were observed.
- File creation and deletion activity suggests potential preparation for illicit transactions.

---

## Created By:
- **Author Name**: Nick Bretke
- **Author Contact**: https://www.linkedin.com/in/NicholasBretzke/
- **Date**: December 23, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**          | **Modified By**   |
|-------------|-------------------------------|-------------------|-------------------|
| 1.0         | Initial draft                 |`December 23, 2025`| `Nicholas Bretzke`   
