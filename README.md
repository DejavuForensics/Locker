# Locker
Retrieval for Locker Malware Analysis


## Commercial Antivirus Limitation


Technically, the modus operandi for the identification of malicious files and servers refers to consult in named blacklist databases. The VirusTotal platform issues the diagnoses regarding malignant characteristics related to files and web servers.

When it comes to suspicious files, VirusTotal issues the diagnostics provided by the world's leading commercial antivirus products. Regarding suspicious web servers, VirusTotal uses the database responsible for sensing virtual addresses with malicious practices.

VirusTotal has Application Programming Interface (APIs) that allow programmers to query the platform in an automated way and without the use of the graphical web interface. The proposed paper employs two of the APIs made available by VirusTotal. The first one is responsible for sending the investigated files to the platform server. The second API, in turn, makes commercial antivirus diagnostics available for files submitted to the platform by the first API.

Initially, the executable malwares are sent to the server belonging to the VirusTotal platform. After that, the executables are analyzed by the 81 commercial antiviruses linked to VirusTotal. Therefore, the antivirus provides its diagnostics for the executables submitted to the platform. VirusTotal allows the possibility of issuing three different types of diagnostics: malware, benign and omission.

Then, through the VirusTotal platform, the proposed paper investigates 81 commercial antiviruses with their respective results presented in Table 1. We used 426 malicious executables for 32-bit architecture. The goal of the work is to check the number of virtual pests cataloged by antivirus. The motivation is that the acquisition of new virtual plagues plays an important role in combating malicious applications. Therefore, the larger the database of malwares blacklisted, the better it tends to be the defense provided by the antivirus.

As for the first possibility of VirusTotal, the antivirus detects the malignity of the suspicious file. In the proposed experimental environment, all submitted executables are public domain malwares. Therefore, in the proposed study, the antivirus hits when it detects the malignity of the investigated executable. Malware detection indicates that the antivirus provides a robust service against cyber-intrusions. As larger the blacklist database, better tends to be the defense provided by the antivirus.

In the second possibility, the antivirus attests to the benignity of the investigated file. Therefore, in the proposed study, when the antivirus attests the benignity of the file, it is a case of a false negative – since all the samples are malicious. That is, the investigated executable is a malware; however, the antivirus attests to benignity in the wrong way.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

Table 1 shows the results of the evaluated 81 antivirus products. Three of these antiviruses scored above 95%. These antiviruses were: ESET-NOD32, MAX, AVG. Malware detection indicates that these antivirus programs provide a robust service against cyber-intrusions.

A major adversity in combating malicious applications is the fact that antivirus makers do not share their malware blacklists due to commercial disputes. Through Table 1 analyse, the proposed work points to an aggravating factor of this adversity: the same antivirus vendor does not even share its databases between its different antivirus programs. Note, for example, that McAfee and McAfee-GW-Edition antiviruses belong to the same company. Their blacklists, though robust, are not shared with each other. Therefore, the commercial strategies of the same company hinder the confrontation with malware. It complements that antivirus vendors are not necessarily concerned with avoiding cyber-invasions, but with optimizing their business income.

Malware detection ranged from 0% to 95.77%, depending on the antivirus being investigated. On average, the 81 antiviruses were able to detect 67.48% of the evaluated virtual pests, with a standard deviation of 26.47%. The high standard deviation indicates that the detection of malicious executables may suffer abrupt variations depending on the antivirus chosen. It is determined that the protection, against cybernetic invasions, is due to the choice of a robust antivirus with a large and updated blacklist.

As for the false negatives, the Zoner and CMC antiviruses wrongly stated that malware was benign in more than 90% of cases. On average, antiviruses attested false negatives in 18.61% of the cases, with a standard deviation of 16.35%. Tackling the benignity of malware can lead to irrecoverable damage. A person or institution, for example, would rely on a particular malicious application when, in fact, it is malware.

On average, the antiviruses were missing in 13.91% of the cases, with a standard deviation of 19.75%. The omission of the diagnosis points to the limitation of these antiviruses that have limited blacklists for detection of malware in real time.

It is included as adversity, in the combat to malicious applications, the fact of the commercial antiviruses do not possess a pattern in the classification of the malwares as seen in Table 2. We choose 3 of 426 malwares samples in order to exemplify the miscellaneous classifications of commercial antiviruses. In this way, the time when manufacturers react to a new virtual plague is affected dramatically. As there is no a pattern, antiviruses give the names that they want, for example, a company can identify a malware as "Malware.1" and a second company identify it as "Malware12310". Therefore, the lack of a pattern, besides the no-sharing of information among the antivirus manufacturers, hinders the fast and effective detection of a malicious application.


###### Table 2 Results of 81 commercial antiviruses:

Antivirus | Deteccion (%) | False Negative (%) | Omission (%)
--------- | ------------- | ------------------ | -------------
ESET-NOD32| 95.77%| 4.23%| 0%|
MAX| 95.54%| 4.23%| 0.23%|
AVG 95.07 2.35 2.58
McAfee 94.84 4.46 0.7
NANO-Antivirus 94.84 5.16 0
Panda 94.6 5.4 0
FireEye 94.6 3.52 1.88
Alibaba 94.37 5.63 0
Cylance 94.37 2.58 3.05
BitDefender 94.37 5.63 0
K7GW 94.37 5.63 0
K7AntiVirus 94.13 5.87 0
MicroWorld-eScan 94.13 5.87 0
Comodo 93.9 5.16 0.94
Kaspersky 93.66 5.63 0.7
GData 93.19 5.63 1.17
VIPRE 93.19 4.23 2.58
Fortinet 92.96 6.1 0.94
VBA32 92.96 7.04 0
Avira 92.72 7.28 0
Microsoft 92.72 6.57 0.7
Emsisoft 92.72 6.81 0.47
Avast 92.49 5.63 1.88
APEX 92.49 7.51 0
Ad-Aware 92.25 7.51 0.23
DrWeb 92.25 7.75 0
Sophos 92.02 6.81 1.17
Zillya 91.08 8.69 0.23
Ikarus 90.85 2.35 6.81
AhnLab-V3 90.38 9.62 0
Qihoo-360 89.44 10.56 0
Jiangmin 88.26 10.8 0.94
McAfee-GW-Edition 88.03 1.88 10.09
SentinelOne 87.56 11.5 0.94
Rising 87.32 11.5 1.17
CrowdStrike 87.32 12.68 0
ALYac 86.85 7.51 5.63
Cybereason 85.92 3.99 10.09
Symantec 84.51 5.4 10.09
Webroot 82.39 17.61 0
TrendMicro-HouseCall 81.22 18.78 0
BitDefenderTheta 80.99 8.69 10.33
Tencent 79.81 19.48 0.7
TrendMicro 79.81 19.95 0.23
Sangfor 79.58 4.23 16.2
Cynet 78.4 4.23 17.37
Cyren 76.76 23.24 0
Yandex 75.12 24.65 0.23
Malwarebytes 75.12 24.88 0
CAT-QuickHeal 73.24 25.82 0.94
Bkav 72.3 26.29 1.41
Lionic 70.42 25.12 4.46
Arcabit 69.25 30.75 0
Paloalto 68.54 31.46 0
eGambit 66.67 24.65 8.69
Elastic 62.44 12.68 24.88
Acronis 61.03 38.97 0
ClamAV 60.8 38.5 0.7
SUPERAntiSpyware 60.09 39.91 0
Kingsoft 43.66 52.58 3.76
ZoneAlarm 43.43 55.4 1.17
TACHYON 41.31 58.69 0
Antiy-AVL 40.61 55.63 3.76
ViRobot 40.38 59.62 0
Baidu 36.38 62.91 0.7
MaxSecure 33.57 54.93 11.5
TotalDefense 32.86 31.22 35.92
F-Secure 28.87 70.89 0.23
Gridinsoft 24.88 49.3 25.82
Invincea 21.13 4.93 73.94
Endgame 18.08 5.87 76.06
Trapmine 16.67 3.52 79.81
F-Prot 16.43 8.69 74.88
Zoner 7.51 92.25 0.23
CMC 4.46 95.54 0
SymantecMobileInsight 0.94 0 99.06
CyrenCloud 0.47 0 99.53
Kaspersky21 0.23 0 99.77
Avast-Mobile 0 23.47 76.53
Babable 0 0.7 99.3
Trustlook 0 0.23 99.77

###### Table 3 Miscellaneous classifications of commercial antiviruses:

Antivírus | VirusShare_0019ac218066b4b77971562d553a9a49 | VirusShare_00462daad93d1950efb7685771793a9f |VirusShare_00cb45c4efd4053cef8bb8567dc0638e
--------- | ------------------------------------------- | ------------------------------------------- | --------------------------------------------
Bkav| W32.AIDetect.malware1 | W32.Common.E76E62C6 |
Lionic | False Negative | False Negative | 
Elastic | malicious (high confidence) | False Negative
MicroWorld-eScan | en:Heur.VIZ.8 | Gen:Variant.Zusy.346759
FireEye | Generic.mg.0019ac218066b4b7 | Generic.mg.00462daad93d1950
CAT-QuickHeal | Trojan.Urausy.C

## Materials and Methods

This paper proposes a database aiming at the classification of 32-bit benign and malware executables. There are 426 malicious executables, and 426 other benign executables. Therefore, our dataset is suitable for learning with artificial intelligence, since both classes of executables have the same amount.

Virtual plagues were extracted from databases provided by enthusiastic study groups as VirusShare. As for benign executables, the acquisition came from benign applications repositories such as sourceforge, github and sysinternals. It should be noted that all benign executables were submitted to VirusTotal and all were its benign attested by the main commercial antivirus worldwide. The diagnostics, provided by VirusTotal, corresponding to the benign and malware executables are available in the virtual address of our database.

The purpose of the creation of the database is to give full possibility of the proposed methodology being replicated by third parties in future works. Therefore, the proposed article, by making its database freely available, enables transparency and impartiality to research, as well as demonstrating the veracity of the results achieved. Therefore, it is hoped that the methodology will serve as a basis for the creation of new scientific works.

## Executable Feature Extraction

The extraction of features of executables employs the process of disassembling. Then, the algorithm, referring to the executable, can be studied and later classified by the neural networks described in the next section. In total, 649 features of each executable are extracted, referring to the groups mentioned above. The pescanner tool are employed in order to extract the features of executables. Next, the groups of features extracted from the executables investigated are detailed.
######	Histogram of instructions, in assembly, referring to the mnemonic.
######	Number of subroutines invoking TLS (Transport Layer Security).
######	Number of subroutines responsible for exporting data (exports).  
######	APIs (Application Programming Interface) used by the executable.
######	Features related to clues that the computer has suffered fragmentation on its hard disk, as well as accumulated invalid boot attempts.  
######	Application execution mode. There are two options:
-	software with a graphical interface (GUI);
-	software running on the console.
######	Features related to the Operating System. Our digital forensics examines if the tested file tries to:
-	identify the current operating system user name;
-	access APIs in order to create and manage current OS user profiles;
-	detect the number of milliseconds since the system was initialized;
-	execute an operation in a specific file;
-	identify the version of the Windows Operating System in use;
-	monitor internal message traffic among system processes;
-	alter the Windows startup settings and contents (STARTUPINFO);  
-	allow applications to access functionality provided by shell of the operating system, as well as alter it; 
-	change the logon messages at Windows OS startup; 
-	change native applications linked to standard dialog boxes in order to open and save files, choosing color and font, among other customizations;
-	configure Windows Server licensing ; 
-	configure Windows Server 2003;
-	change the system's power settings;
-	open a process, service, or native library of the Operating System; 
-	exclude the context of certificates linked to the Operating System; 
-	copy an existing file to a new file; 
-	create, open, delete, or alter a file;
-	create and execute new process(s); 
-	create new directory(s); 
-	search for specific file(s);  
-	create a service object and add it to the control manager database for a certain service; 
-	encrypt data. It is a typical strategy of ransomwares which sequester the victim's data through cryptography. To decrypt the data, the invader asks the user for a monetary amount so that he victim can have all his data back;
-	access file systems, devices, processes, threads and error handling of the system;
-	change the sound and audio device properties of the system;
-	access graphical content information for monitors, printers, and other Windows OS output devices; 
-	use and/or monitor the USB port;
-	control a driver of a particular device; 
-	investigate if a disk drive is a removable, fixed, CD / DVD-ROM, RAM or network drive;
######	Features related to Windows Registry (Regedit). It is worth noting that the victim may not be free from malware infection even after its detection and elimination. The persistence of malefactions, even after malware exclusion, occurs due to the insertion of malicious entries (keys) in Regedit. Then, when the operating system boots, the cyber-attack restarts because of the malicious key invoking the vulnerability exploited by malware (eg: redirect Internet Explorer home page). Then, our antivirus audits if the suspicious application tries to:
-	detect the NetBIOS name of the local computer. This name is established at system startup, when the system reads it in the registry (Regedit);
-	terminate a key of a specific registry; 
-	create a key from in a specific registry. If the key already exists in Regedit, then it will be read; 
-	delete a key and its values in Regedit; 
-	enumerate and   open subkeys of a specific open registry. 
######	Features related to spywares such as keyloggers (capture of keyboard information in order to theft of passwords and logins) and screenloggers (screen shot of the victim). Our antivirus audits if the analyzed file tries to:
-	detect in which part of the victim's screen there was an update;
-	identify the screen update region by copying it to a particular region;
-	capture AVI movies and videos from web cameras and other video hardware; 
-	capture information on electronic voting, specifically from the company Optical Vote-Trakker;
-	copy an array of keyboard key states. Such strategy is typical of keyloggers
-	monitor user's Internet activity and private information;
-	collect online bank passwords and other confidential information and to send the data to invader creator;
-	access a computer from remote locations, stealing passwords, Internet banking and personal data; 
-	create a BHO (Browser Helper Object) which is executed automatically every time when the web browser is started. It fits to emphasize that BHOs are not impeded by personal firewalls because they are identified as part of the browser. In a distorted way, BHOs are often used by adware and spyware in order to record keyboard and mouse entries
-	locate passwords stored on a computer.
######	Features related to Anti-forensic Digital which are techniques of removal, occultation and subversion of evidences with the goal of reducing the consequences of the results of forensic analyzes. Our antivirus investigates if the file tries to:
-	Suspend its own execution until a certain timeout interval has elapsed. A typical malware strategy that maintains itself inactive until the end of commercial antivirus quarantine;
-	Disable the victim's defense mechanisms, including Firewall and Antivirus;
-	disable automatic Windows updates;
-	detect if the own file is being scanned by an debugger of the Operating System;   
-	retrieve information about the first and next process found in an Operating System snapshot. Such strategy is typical of malwares that aim to corrupt backups and restore points of the Operating System;
-	hide one file in another. This strategy is named, technically, steganography which aims to hide malware in a benign program in the Task Manager;
-	disguise its own name in the Task Manager;
-	make use of libraries associated with Hackers Encyclopedia 2002;
-	Create a ZeroAcess cyber-attack type through firmware updates of hardware devices (eg, hard drive controlled).
######	Features related to the creation of GUI (Graphical User Interface) of the suspicious program. Our antivirus audits if the suspect file tries to: 
-	create a GUI at runtime; 
-	use DirectX which allows multimedia applications to draw 2D graphics; 
-	create a module that contains bitmap compression and decompression routines used for Microsoft Video for Windows;
-	create 3D graphics related to utilitarian functions used by OpenGL; 
-	detect shapes through computer vision and digital image processing;
-	access functionalities in order to create and to manage screen windows and more basic controls such as buttons and scrollbars, receive mouse and keyboard input, and other functionalities associated with the Windows GUI. This includes widgets like status bars, progress bars, toolbars, and guides; 
######	Features related to the illicit forensic of the RAM (main memory) of the local system. Our antivirus investigates if the suspicious application tries to:
-	access information in specific regions of main memory;
-	read data from an area of memory occupied by a specific process;
-	write data to a memory area in a specific process;
-	reserve, confirm or alter the status of a page region in the virtual address space of a process.
######	Features related to network traffic. It is checked if the suspect file tries to:
-	query DNS servers;
-	send request to an HTTP server; 
-	monitor information of the headers of computer data packets associated with an HTTP request;
-	send an ICMP IPv4 echo request; 
-	send an SNMP request used to monitor LAN equipment;
-	terminate the Internet connection;
-	create an FTP or HTTP session at runtime; 
-	fragment a URL at runtime; 
-	query a server in order to determine the amount of traffic data available; 
-	identify the connection state of the local system in relation to the Internet; 
-	initialize the use of an application of the WinINet functions (Windows API for creating and using the application using the Internet); 
-	read data from network packets made from previous local system requests (typical behavior of sniffers); 
-	overwrite data in a local system network packet; 
-	manage local and remote network systems; 
-	create a network socket on the local system. In a conventional application, the server sends data to the client (s). In an opposite way, in malware, the victim sends the data (images, digits) to the server. Therefore, malware can create sockets on the local system waiting (listen) for a remote malicious computer to request a connection and, then, receive the victim's private information;
-	receive data of a socket. Typical strategy of backdoors when the victim starts receiving remote commands; 
-	send data to a socket. Typical strategies of spywares which, after capturing innermost information, they send them to a malicious remote computer; 
######	Features related to utility applications programs. Our created antivirus checks if the suspicious file tries to:
-	reproduce videos/audios through Windows Media Player; 
-	change the shortcut icon and Internet default settings exhibited in the Explorer toolbar address bar; 
-	alter the Wordpad configurations;
-	alter the configurations of sockets, specifically, managed by Internet Explorer; 
-	alter Outlook Express configurations and to access the victim’s  e-mail list; 
-	access information linked to the Microsof Office; 
-	alter the configurations of the Adobe System’s suite;
-	change the system's disk cleanup configurations; 
-	alter the settings of native digital electronic games and others linked to companies Tycoon and Electronic Arts;
-	change Google Inc updates settings; 
-	use Visual Basic. Such strategy is typical of macro viruses that are intended to infect applications that support macro language such as web browsers, Microsoft Office, and Adobe Systems.
-	alter the access settings to Wikipedia.
