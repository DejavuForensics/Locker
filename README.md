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
ESET-NOD32 95.77 4.23 0
MAX 95.54 4.23 0.23
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

Antivírus | VirusShare_001627d61a1bde3478ca4965e738dc1e | VirusShare_075efef8c9ca2f675be296d5f56406fa | VirusShare_0dab86f850fd3dafc98d0f2b401377d5
--------- | ------------------------------------------- | ------------------------------------------- | --------------------------------------------



## Materials and Methods

This paper proposes a database aiming at the classification of 32-bit benign and malware executables. The database is referred to as REWEMA (Retrieval of 32-bit Windows Architecture Executables Applied to Malware Analysis). There are 426 malicious executables, and 426 other benign executables. Therefore, the REWEMA base is suitable for learning with artificial intelligence, since both classes of executables have the same amount.

Virtual plagues were extracted from databases provided by enthusiastic study groups as VirusShare. As for benign executables, the acquisition came from benign applications repositories such as sourceforge, github and sysinternals. It should be noted that all benign executables were submitted to VirusTotal and all were its benign attested by the main commercial antivirus worldwide. The diagnostics, provided by VirusTotal, corresponding to the benign and malware executables are available in the virtual address of our database.

The purpose of the creation of the database is to give full possibility of the proposed methodology being replicated by third parties in future works. Therefore, the proposed article, by making its database freely available, enables transparency and impartiality to research, as well as demonstrating the veracity of the results achieved. Therefore, it is hoped that the methodology will serve as a basis for the creation of new scientific works.
