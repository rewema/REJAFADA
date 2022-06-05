# REJAFADA
(Retrieval of Jar Files Applied to Dynamic Analysis)

    Pinheiro, R.P., Lima, S.M.L., Souza, D.M. et al. 
    Antivirus applied to JAR malware detection based on runtime behaviors. 
    Scientific Reports - Nature 12, 1945 (2022). 
    https://doi.org/10.1038/s41598-022-05921-5
    
## Limitation of Commercial Antivirus

Although it has been questioned for more than a decade, the modus operandi of antiviruses is based on signatures when the suspect file is consulted on datasets named blacklist. Therefore, it is enough that the hash of the investigated file not to be in the blacklist of the antivirus in order to malware not to be detected. The hash functions as a unique identifier for a given file. Then, given the limitations of commercial antiviruses, it is not a difficult task to develop and to distribute variants of a malicious application. To do this, it is enough to make small alterations in the original malware with routines that, effectively, do not have any usefulness like repetition loops and conditional branches without instructions in their scopes. These alterations without usefulness, however, they turn the hash of the modified malware different from the hash of the original malware. Consequently, malware, incremented with null routines, will not be detected by the antivirus which cataloged the original malware. It should to emphasize the existence of botnets responsible for creating and distributing, in automated form, variants of a same original malware. It is concluded that antiviruses, based on signatures, have null effectiveness when submitted to variants of a same malware.

Through the VirusTotal platform, this proposed paper investigates 86 commercial antiviruses with their respective results presented in Table 1. We used 998 Jar malicious obtained from the base REJAFADA. The goal of the paper is to verify the amount of virtual plagues cataloged by antivirus. The motivation is that the acquisition of new virtual plagues plays an important role in combating malicious applications. Therefore, as larger is the dataset, named blacklist, better tends to be the defense provided by the antivirus. Fig. 1 shows the diagram of the methodology proposed in diagram of blocks. Initially, Jar malwares are sent to the server belonging to the VirusTotal platform. After this, the Jar Files are analyzed by the 86 commercial antiviruses from VirusTotal. Then, the antiviruses provide their diagnostics for Jar files submitted to the server. VirusTotal allows the possibility of emission of three different types of diagnostics: malware, benign and omission.

As for the first possibility of VirusTotal, the antivirus detects the malignity of the suspicious file. In the proposed experimental environment, all submitted files are malware documented by incident responders. Then, the antivirus hits when it detects the malignity of the file investigated. Malware detection indicates that the antivirus provides a robust service against cyber-invasions. In the second possibility, the antivirus attests to the benignity of the investigated file. Therefore, in the proposed study, when the antivirus alleges the benignity of the file, it is a case of false negative because all submitted samples are malicious. That is, the file investigated is malware, however, the antivirus attests to benignity in a mistaken way. In the third possibility, the antivirus does not emit opinion about the suspect file. The omission indicates that the file investigated has never been evaluated by the antivirus so little it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

Table 1 shows the results of the 86 antiviruses products evaluated. The McAfee-GW-Edition antivirus achieved the best performance by being able to detect 99.10% of the investigated malwares. A major adversity in order to combat malicious applications is the fact that the antivirus manufacturers do not share their malwares blacklists due to commercial disputes. Through the analysis of Table 1, the proposed work points to an aggravating factor of this adversity: the same antivirus manufacturer does not share their databases amongtheir different antiviruses. Observe, for example, that McAfee-GW-Edition and McAfee antiviruses belong to a same company. Their blacklists, though robust, are not shared amongst themselves. Therefore, the commercial strategies, of a same company, disturb the confrontation against malwares. It complements that antivirus manufacturers are not necessarily concerned in avoiding cyber-invasions, but in optimizing their business incomes.

Malware detection ranged from 0% to 99.10%, depending on the investigated antivirus. On average, the 86 antiviruses were able to detect 34.95% of the evaluated virtual plagues, with a standard deviation of 40.92. The high standard deviation indicates that the detection of malicious files can suffer abrupt variations depending on the chosen antivirus. It is determined that the protection, against cybernetic invasions, is in function of the choice of a robust antivirus with a large and updated blacklist. On average, antiviruses attested false negatives in 33.90% of the cases, with a standard deviation of 40.45. To attest the benignity of malware can implicate in unrecoverable damages. A person or institution, for instance, would start to trust on a certain malicious application when, in fact, it is a malware. Still as an unfavorable aspect, about 31.39% of antiviruses did not express an opinion on any of the 998 malicious samples. On average, the antiviruses were omitted in 31.15% of the cases, with a standard deviation of 45.61%. The omission of the diagnosis points to the limitation of antiviruses as for the malwares detection in real time.

It is included as adversity, in the combat to malicious applications, the fact of the commercial antiviruses do not have a pattern in classification of malwares as seen in Table 2. We chose 3 of the 998 Jar malwares in order to exemplify the miscellaneous of classifications given by antivirus commercial activities. As there is no pattern, the antiviruses give the names that they want, for example, a company can identify a Jar malware as "Android: RuFraud-I" and a second company identify it as "Artemis! 9EF6966B98A5". Therefore, the lack of a pattern disturbs the cyber-security strategies since each category of malware must have different treatments (vaccines). It is concluded that it is impracticable to a supervised machine learning adopts pattern recognition as for categories of Jar malwares. Due to this confusing tangle of MultiClass Classification, provided by specialists (antiviruses) as seen in Table 4, it is statistically improbable that any machine learning technique will acquire generalization capability.

###### Table 1 – Results of 86 commercial antiviruses.

| Antivirus            | Detection (%) | False negative (%) | Omission (%) |
|----------------------|---------------|--------------------|--------------|
| McAfee-GW-Edition    | 99.10         | 0.90               | 0.00         |
| NANO-Antivirus       | 97.70         | 2.20               | 0.10         |
| AegisLab             | 97.60         | 2.10               | 0.30         |
| Kaspersky            | 96.80         | 2.90               | 0.30         |
| ZoneAlarm            | 96.70         | 2.90               | 0.40         |
| Avast                | 96.60         | 3.30               | 0.10         |
| AVG                  | 96.60         | 3.30               | 0.10         |
| ESET-NOD32           | 95.90         | 4.10               | 0.00         |
| McAfee               | 95.60         | 4.40               | 0.00         |
| Avira                | 94.80         | 3.30               | 1.90         |
| Sophos               | 94.70         | 5.00               | 0.30         |
| Symantec             | 94.10         | 5.90               | 0.00         |
| Ikarus               | 93.60         | 0.70               | 5.70         |
| MAX                  | 91.00         | 8.80               | 0.20         |
| TrendMicro-HouseCall | 89.70         | 5.70               | 4.60         |
| Emsisoft             | 88.50         | 11.40              | 0.10         |
| GData                | 88.30         | 10.00              | 1.70         |
| BitDefender          | 88.00         | 11.20              | 0.80         |
| Tencent              | 87.00         | 12.80              | 0.20         |
| Arcabit              | 86.70         | 13.30              | 0.00         |
| MicroWorld-eScan     | 86.20         | 13.60              | 0.20         |
| Microsoft            | 84.50         | 15.50              | 0.00         |
| Ad-Aware             | 82.50         | 15.30              | 2.20         |
| DrWeb                | 82.10         | 17.90              | 0.00         |
| TrendMicro           | 80.20         | 9.20               | 10.60        |
| Zillya               | 73.70         | 20.00              | 6.30         |
| VBA32                | 73.10         | 26.80              | 0.10         |
| Cyren                | 70.80         | 28.80              | 0.40         |
| F-Prot               | 66.30         | 33.40              | 0.30         |
| Comodo               | 60.50         | 39.30              | 0.20         |
| F-Secure             | 60.00         | 36.60              | 3.40         |
| TotalDefense         | 58.50         | 41.50              | 0.00         |
| Yandex               | 46.00         | 53.90              | 0.10         |
| CAT-QuickHeal        | 35.60         | 64.40              | 0.00         |
| Jiangmin             | 34.30         | 63.50              | 2.20         |
| Qihoo-360            | 33.50         | 64.40              | 2.10         |
| AhnLab-V3            | 17.60         | 82.40              | 0.00         |
| ClamAV               | 16.50         | 82.30              | 1.20         |
| Fortinet             | 16.30         | 83.60              | 0.10         |
| AVware               | 13.10         | 86.70              | 0.20         |
| K7GW                 | 10.50         | 89.50              | 0.00         |
| K7AntiVirus          | 10.30         | 89.70              | 0.00         |
| Antiy-AVL            | 6.10          | 93.40              | 0.50         |
| Webroot              | 4.00          | 89.00              | 7.00         |
| Panda                | 3.40          | 96.60              | 0.00         |
| ViRobot              | 3.30          | 96.70              | 0.00         |
| Rising               | 2.90          | 96.10              | 1.00         |
| TheHacker            | 1.10          | 98.80              | 0.10         |
| Kingsoft             | 0.70          | 99.20              | 0.10         |
| Invincea             | 0.60          | 0.10               | 99.30        |
| Zoner                | 0.60          | 97.10              | 2.30         |
| Baidu                | 0.60          | 99.00              | 0.40         |
| VIPRE                | 0.50          | 99.50              | 0.00         |
| Malwarebytes         | 0.30          | 94.10              | 5.60         |
| Cylance              | 0.20          | 0.00               | 99.80        |
| WhiteArmor           | 0.20          | 91.30              | 8.50         |
| Alibaba              | 0.20          | 98.50              | 1.30         |
| ALYac                | 0.10          | 95.80              | 4.10         |
| Bkav                 | 0.10          | 97.60              | 2.30         |
| Paloalto             | 0.00          | 0.00               | 100.00       |
| SentinelOne          | 0.00          | 0.00               | 100.00       |
| Endgame              | 0.00          | 0.00               | 100.00       |
| CrowdStrike          | 0.00          | 0.00               | 100.00       |
| Agnitum              | 0.00          | 0.00               | 100.00       |
| ByteHero             | 0.00          | 0.00               | 100.00       |
| Norman               | 0.00          | 0.00               | 100.00       |
| Ahnlab               | 0.00          | 0.00               | 100.00       |
| AntiVir              | 0.00          | 0.00               | 100.00       |
| Commtouch            | 0.00          | 0.00               | 100.00       |
| VirusBuster          | 0.00          | 0.00               | 100.00       |
| NOD32                | 0.00          | 0.00               | 100.00       |
| eSafe                | 0.00          | 0.00               | 100.00       |
| eTrust-Vet           | 0.00          | 0.00               | 100.00       |
| Authentium           | 0.00          | 0.00               | 100.00       |
| Prevx                | 0.00          | 0.00               | 100.00       |
| Sunbelt              | 0.00          | 0.00               | 100.00       |
| PCTools              | 0.00          | 0.00               | 100.00       |
| a-squared            | 0.00          | 0.00               | 100.00       |
| Command              | 0.00          | 0.00               | 100.00       |
| SAVMail              | 0.00          | 0.00               | 100.00       |
| FileAdvisor          | 0.00          | 0.00               | 100.00       |
| Ewido                | 0.00          | 0.00               | 100.00       |
| Webwasher-Gateway    | 0.00          | 0.00               | 100.00       |
| CMC                  | 0.00          | 99.80              | 0.20         |
| nProtect             | 0.00          | 99.90              | 0.10         |
| SUPERAntiSpyware     | 0.00          | 100.00             | 0.00         |

###### Table 2 – Miscellaneous classifications of commercial antiviruses.

| Antivirus            | VirusShare_9ef6966b98a5c9ce524bc9a24dc9c488 | VirusShare_bee5a7c75b6a5b9a41634dce2ae21128 | VirusShare_93fa0564cfc049a16768d11b34dd60e8 |
|----------------------|---------------------------------------------|---------------------------------------------|---------------------------------------------|
| McAfee-GW-Edition    | Artemis!Trojan                              | Artemis                                     | PWS-Zbot.gen.jr                             |
| NANO-Antivirus       | Trojan.Android.SMSSend.numyx                | Trojan.Android.Opfake.oefcg                 | Trojan.Java.CVE20113544.cspflc              |
| AegisLab             | Troj.Sms.Androidos!c                        | SUSPICIOUS                                  | Troj.W32.Generic!c                          |
| Kaspersky            | HEUR:Trojan-SMS.AndroidOS.Fakelogo.a        | HEUR:Trojan-SMS.AndroidOS.Fakelogo.a        | HEUR:Trojan.Win32.Generic                   |
| ZoneAlarm            | HEUR:Trojan-SMS.AndroidOS.Fakelogo.a        | HEUR:Trojan-SMS.AndroidOS.Fakelogo.a        | HEUR:Trojan.Win32.Generic                   |
| Avast                | Android:RuFraud-I                           | Android:RuFraud-I                           | Java:CVE-2011-3544-BD                       |
| AVG                  | Android:RuFraud-I                           | Android:RuFraud-I                           | Java:CVE-2011-3544-BD                       |
| ESET-NOD32           | Android/TrojanSMS.Agent.K                   | Android/TrojanSMS.Agent.K                   | a variant of Java/Exploit.CVE-2011-3544.DF  |
| McAfee               | Artemis!9EF6966B98A5                        | Artemis!BEE5A7C75B6A                        | RDN/Generic                                 |
| Avira                | ANDROID/SmsAgent.CQ.Gen                     | ANDROID/SmsAgent.CQ.Gen                     | EXP/CVE-2011-3544                           |
| Sophos               | Andr/Jifake-B                               | Andr/Opfake-A                               | Mal/Generic-S                               |
| Symantec             | Android.Fakemini                            | Android.Fakemini                            | Trojan.MalJava                              |
| Ikarus               | Trojan.AndroidOS.FakeInst                   | Trojan.AndroidOS.FakeInst                   | Java.CVE                                    |
| MAX                  | Malware                                     | malware                                     | malware                                     |
| TrendMicro-HouseCall | Suspicious_GEN.F47V0322                     | AndroidOS_OPFAKE.A,                         | Suspicious_GEN.F47V0322                     |
| Emsisoft             | Android.Trojan.FakeInst.CB                  | Android.Trojan.FakeInst.CB                  | Gen:Variant.Barys.841                       |
| GData                | Android.Trojan.FakeInst.CB                  | Android.Trojan.FakeInst.CB                  | Gen:Variant.Barys.841                       |
| BitDefender          | Android.Trojan.FakeInst.CB                  | Android.Trojan.FakeInst.CB                  | Gen:Variant.Barys.841                       |
| Tencent              | Trojan.Android.FakeLogo.aa                  | Trojan.Android.FakeLogo.aa                  | Win32.Trojan.Jorik.Hvje                     |
| Arcabit              | Android.Trojan.FakeInst.CB                  | Android.Trojan.FakeInst.CB                  | Trojan.Barys.841                            |
| MicroWorld-eScan     | Android.Trojan.FakeInst.CB                  | Benign                                      | Gen:Variant.Barys.841                       |
| Microsoft            | Benign                                      | Benign                                      | Exploit:Java/CVE-2011-3544                  |
| Ad-Aware             | Benign                                      | Benign                                      | Benign                                      |
| DrWeb                | Android.SmsSend.681.origin                  | Android.SmsSend.176                         | Exploit.CVE2011-3544.2                      |
| TrendMicro           | AndroidOS_OPFAKE.AJ                         | AndroidOS_OPFAKE.A,                         | EXPL_CVE20113544                            |
| Zillya               | Benign                                      | Benign                                      | Trojan.Jorik.Win32.159683                   |
| VBA32                | Trojan-SMS.AndroidOS.Opfake.ap              | Trojan-SMS.AndroidOS.Opfake.aj              | TrojanDownloader.CodecPack                  |
| Cyren                | AndroidOS/Opfake.J                          | AndroidOS/Jifake.N                          | ZIP/Trojan.CYHN-7                           |
| F-Prot               | AndroidOS/Opfake.J                          | AndroidOS/Jifake.N                          | Benign                                      |
| Comodo               | Benign                                      | UnclassifiedMalware                         | Benign                                      |
| F-Secure             | Trojan:Android/FakeLogo.B                   | Benign                                      | Gen:Variant.Barys.841                       |
| TotalDefense         | Benign                                      | AndroidOS/Tnega.UILUYb                      | Benign                                      |
| Yandex               | Benign                                      | Benign                                      | Trojan.Kryptik!sphh5U5K2cs                  |
| CAT-QuickHeal        | Android.Fakelogo.A                          | Android.Fakelogo.A                          | Exp.JAVA.Generic.AL                         |
| Jiangmin             | Trojan/AndroidOS.gy                         | Trojan/AndroidOS.ftg                        | Trojan/Jorik.gdfq                           |
| Qihoo-360            | Trojan.Android.Gen                          | Trojan.Android.Gen                          | virus.exp.20113544.1                        |
| AhnLab-V3            | Android-Trojan/Opfake.1b4a                  | Android-Trojan/Opfake.1b4a                  | Benign                                      |
| ClamAV               | Benign                                      | Benign                                      | Benign                                      |
| Fortinet             | Android/Agent.FP!tr                         | Android/Agent.FP!tr                         | W32/Kryptik.WEF!tr                          |
| AVware               | Trojan.AndroidOS.FakeLogo.b                 | Trojan.AndroidOS.FakeLogo.b                 | LooksLike.Java.Malware.j                    |
| K7GW                 | Trojan                                      | Trojan                                      | Trojan-Downloader                           |
| K7AntiVirus          | Benign                                      | Benign                                      | Trojan-Downloader                           |
| Antiy-AVL            | Trojan[SMS]/Android.Opfake                  | Trojan[SMS]/Android.Opfake                  | Trojan/Win32.Mokes                          |
| Webroot              | Benign                                      | Benign                                      | W32.Malware.Heur                            |
| Panda                | Benign                                      | Benign                                      | Generic                                     |
| ViRobot              | Benign                                      | Benign                                      | Benign                                      |
| Rising               | Benign                                      | Benign                                      | Benign                                      |
| TheHacker            | Benign                                      | Benign                                      | Benign                                      |
| Kingsoft             | Android.Troj.at_FakeOpera.h.(kcloud)        | Android.Troj.Opfake.aj.v.(kcloud)           | VIRUS_UNKNOWN                               |
| Invincea             | Omission                                    | Omission                                    | heuristic                                   |
| Zoner                | Benign                                      | Benign                                      | Benign                                      |
| Baidu                | Omission                                    | Omission                                    | Omission                                    |
| VIPRE                | Benign                                      | Benign                                      | LooksLike.Java.Malware.j                    |
| Malwarebytes         | Benign                                      | Benign                                      | Benign                                      |
| Cylance              | Omission                                    | Omission                                    | Unsafe                                      |
| WhiteArmor           | Malware.HighConfidence                      | Malware.HighConfidence                      | Benign                                      |
| Alibaba              | A.H.Pay.Erop.C                              | A.H.Pay.Erop.D                              | Benign                                      |
| ALYac                | Benign                                      | Benign                                      | Benign                                      |
| Bkav                 | Benign                                      | Benign                                      | Benign                                      |
| Paloalto             | Omission                                    | Omission                                    | Omission                                    |
| SentinelOne          | Omission                                    | Omission                                    | Omission                                    |
| Endgame              | Omission                                    | Omission                                    | Omission                                    |
| CrowdStrike          | Omission                                    | Omission                                    | Omission                                    |
| Agnitum              | Omission                                    | Omission                                    | Omission                                    |
| ByteHero             | Omission                                    | Omission                                    | Omission                                    |
| Norman               | Omission                                    | Omission                                    | Omission                                    |
| ahnlab               | Omission                                    | Omission                                    | Omission                                    |
| AntiVir              | Omission                                    | Omission                                    | Omission                                    |
| Commtouch            | Omission                                    | Omission                                    | Omission                                    |
| VirusBuster          | Omission                                    | Omission                                    | Omission                                    |
| NOD32                | Omission                                    | Omission                                    | Omission                                    |
| eSafe                | Omission                                    | Omission                                    | Omission                                    |
| eTrust-Vet           | Omission                                    | Omission                                    | Omission                                    |
| Authentium           | Omission                                    | Omission                                    | Omission                                    |
| Prevx                | Omission                                    | Omission                                    | Omission                                    |
| Sunbelt              | Omission                                    | Omission                                    | Omission                                    |
| PCTools              | Omission                                    | Omission                                    | Omission                                    |
| a-squared            | Omission                                    | Omission                                    | Omission                                    |
| Command              | Omission                                    | Omission                                    | Omission                                    |
| SAVMail              | Omission                                    | Omission                                    | Omission                                    |
| FileAdvisor          | Omission                                    | Omission                                    | Omission                                    |
| Ewido                | Omission                                    | Omission                                    | Omission                                    |
| Webwasher-Gateway    | Omission                                    | Omission                                    | Omission                                    |
| CMC                  | Benign                                      | Benign                                      | Benign                                      |
| nProtect             | Benign                                      | Benign                                      | Benign                                      |
| SUPERAntiSpyware     | Benign                                      | Benign                                      | Benign                                      |

## Materials and Methods

The present paper aims to elaborate the REJAFADA (Retrieval of Jar Files Applied to Dynamic Analysis), a dataset which allows the classification of files with Jar extension between benign and malwares. The REJAFADA is composed of 998 malware Jar files and 998 other benign Jar files. The REJAFADA dataset, consequently, is suitable for learning endowed with AI (Artificial Intelligence), considering that the Jar files presented the same amount in the different classes (malware and benign). The goal is that tendentious classifiers, in relation to a certain class, do not have their success taxes favored.

In relation to virtual plagues, REJAFADA extracted malicious Jar files from VirusShare which is a repository of malware samples to provide security researchers, incident responders, forensic analysts, and the morbidly curious access to samples of live malicious code. 
In order to catalog the 998 samples of jar malwares, it was necessary to acquire and analyze, by authorial script, about 3 million malwares from the reports updated by VirusShare daily. 
With respect to benign Jar files, the catalog was given from application repositories such as Java2s.com, and findjar.com. All of the benign files have been audited by VirusTotal. Then, the benign Jar files, contained in REJAFADA, had their benevolence attested by the main commercial antiviruses of the world. The obtained results corresponding to the analyses of the benign and malware Jar files, resulting from the VirusTotal audit, are available for consultation at the virtual address of REJAFADA.

The goal of creation of REJAFADA dataset is to give full possibility of the proposed methodology being replicated by third parties in future works. Then, REJAFADA makes available, freely, of all their samples such as benign as malwares:

• VirusTotal audits;

• Dynamic analysis of Cuckoo Sandbox.

REJAFADA also makes available in its virtual address, its 998 benign Jar files. In addition, our dataset displays the list of all other 998 Jar files, this time, malwares. Then, there is the possibility of the acquisition of all the malwares, employed by REJAFADA, through the agreement establishment and submission to the rules of use of ViruShare. It is concluded that our REJAFADA dataset enables transparency and impartiality to the research, in addition to demonstrating the veracity of the achieved results. Therefore, it is expected that REJAFADA serves as base for the creation of new scientific works aiming NGAVs.

## Dynamic Feature Extraction

The features of Jar files originate through the dynamic analysis of suspicious files. Therefore, in our methodology, the malware is executed in order to infect, intentionally, the JVM installed in Windows 7 audited, in real time (dynamic), by the Cuckoo Sandbox. In total, 6,824 features are generated of each Jar file, regarding the monitoring of the suspect file in the proposed controlled environment. Next, the groups of features are detailed.

######	Features related to Code Injection, a technique used by an attacker to introduce code into vulnerable programs and change their behavior. The auditory checks whether the tested file try to:
-	execute a process and inject code while it is uncompressed;
-	injecting code into a remote process using one of the following functions: CreateRemoteThread or NtQueueApcThread.
	
######	Features related to Keyloggers, programs that record all user-entered keyboard entries, for the primary purpose of illegally capturing passwords and other confidential information. Checks whether the file being investigated tries to:
-	create mutexes of Ardamax or Jintor keyloggers.
	
######	Features related to the search for other possibly installed programs. The goal is to verify that the audited file searches for:
-	discover where the browser is installed, if there is one in the system.
-	discover if there is any sniffer or a installed network packet analyzer.

######	Features related to disable Windows components:
-	It is audited if the suspect file tries to disable any of the windows programs: CMD.exe, Device Manager, or Registry Editor, by manipulating the Windows registry (\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Disable).

######	Features related to packing and obfuscation. The proposed digital forensic verifies if the suspect file:
-	has packet or encrypted information indicative of packing
-	creates a slightly modified copy of itself (polymorphic packing);
-	is compressed using UPX (Ultimate Packer for Executables) or VMProtect (software used in order to obfuscate code and virtualize programs).
-	
######	Features related to persistence, functionality of backup information in a system, without the need to register them before. Our Sandbox audit if suspicious file tries to:
-	use javascript in a registry key value in regedit.
-	create an ADS (Alternate Data Stream), NTFS feature that contains information to locate a specific file by author or title, used maliciously because as the information that is present in it does not change the characteristics of the file associated with it, transform them into an ideal option for building rootkits, because they are hidden (steganography);
-	install a self-executing in windows startup (autorun);
-	install a native executable to run at the beginning of windows boot.

######	Features related to Windows 7 OS (Regedit):
-	Changes in associations between file extensions and software installed on the machine (HKEY_CLASSES_ROOT);
-	Changes to the current user information (HKEY_CURRENT_USER);
-	Driver corruption (HKEY_LOCAL_MACHINE);
-	Changes in Windows appearance settings and settings made by users, such as wallpaper, screensaver, and themes (HKEY_USERS);
-	Changes in Hardware Settings (HKEY_CURRENT_CONFIG).

######	Features related to native Windows 7 OS programs. It is audited, during its execution, if the suspicious file tries to:
-	allocate write and read memory for execution, usually for unpacking;
-	identify analysis tools installed by the location of the installation of said tool;
-	detect the presence of antivirus Avast and BitDefender, through libraries (*. Dll file) present when these antivirus are installed;
-	identify installed antivirus products through the installation directory or registry keys;
-	modify software restriction policies for the purpose of disabling the antivirus;
-	check for known devices or windows from forensic tools and debuggers;
-	detect the presence of the Wine emulator;
-	install yourself on AppInit to inject into new processes;
-	divert AppLocker through a Powershell script, running regsvr32;

######	Features related to Windows 7 Boot OS. Audit if suspicious file tries to:

-	modify boot configurations;
-	install a bootkit (malicious files for the purpose of changing and infecting the master boot record of the computer) through modifications to the hard disk;
-	create office documents in the file system;
-	create a Windows executable file on the file system;
-	create or configure registry keys with a long string of bytes, most likely to store a binary file or configure a malware;
-	create a service;
-	create a shortcut to an executable file;
-	use the Windows APIs to generate a cryptographic key;
-	generate a malicious DDE document (Dynamic Data Exchange, originally used to facilitate the transfer of data between Microsoft word and other microsoft office programs, but with its function deflected by hackers in the present time, in order to try to introduce lines of malicious code, microsoft office;
-	erase your original disk binary;
-	load a device driver;
-	release and execute a binary file;
-	remove evidence that a file has been downloaded from the Internet without the user being aware of it;
-	create files, registry keys and / or mutexes related to Fakerean Fraudtool malware;
-	use GetSystemMetrics, a Windows function that was originally used to collect measurements of graphics on screen, now used by hackers in conjunction with malicious Ransomware techniques;
-	create files related to the PWDump / FGDump tools, which were originally used for password management, and are used by hackers to bypass Windows security mechanisms;
-	connect to an IP BitTorrent Bleepchat (encrypted chat service and P2P from BitTorrent);
-	connect to IP's related to Chinese instant messaging services, such as QQ, used by hackers maliciously;
-	access Bitcoin / ALTCoin portfolios, which can be used to transfer funds into illegal transactions.

######	Features that seek to disable features of Windows 7 OS and other utilities. The audit checks to see if the file can:

-	modify system policies to prevent the launch of specific applications or executables;
-	disable browser security warnings;
-	disable Windows security features and properties;
-	disable google SPDY network protocol support in Mozilla Firefox browsers to increase the ability of an internet malware to gain access to sensitive information;
-	disable system restore;
-	disable the Windows Error Reporting and Windows Auto Update features.

######	Features related to executable files. The proposed digital forensic verifies that the suspect file tries to:

-	use the BITSAdmin tool (command line tool originally used to download and upload files, as well as track the progress of this transfer, but which malicious hackers use) to download any file;
-	halt at least one process during its execution;
-	execute the WaitFor statement (executable present in Windows since its version 7, originally has the function of synchronizing events between networked computers, but which evildoers use in harmful ways), possibly to synchronize malicious activities.

######	Features related to memory dump, process in which the contents of RAM memory is copied for diagnostic purposes. The proposed digital forensics audits if the application tries to:
-	find malicious URL’s in memory dump processing;
-	find evidence of the presence and use of the yara program, used to perform memory dump's.

######	Features related to crypto-coin mining:
-	It is audited if the suspect application tries to connect to mining pools, the goal is to generate virtual currencies without the cognition (and not benefiting) the computer owner.

######	Features related to system modifications:
-	It is audited if the suspect application tries to create or modify system certificates, security center warnings, user account control behaviors, desktop wallpaper, or ZoneTransfer.ZoneID values in the ADS(Alternate Data Stream).

######	Features related to Microsoft Office. Checks if the tested application tries to:
-	create a suspicious VBA object
-	run microsoft office processes inserted in a command line interface packed object.

######	Feature related to POS (point of sale), type of attack that aims to obtain the information of credit and debit cards of victims. It is investigated if the audited file tries to:
-	create files related to malware POS Alina;
-	contact servers related to malware POS Alina;
-	contact botnets related to malware POS blackpos;
-	create mutexes related to malware POS decebel;
-	create mutexes and registry keys related to POS Dexter malware;
-	create mutexes and registry keys related to malware POS jackpos;
-	contact botnets related to malware POS jackpos;
-	contact servers related to POS poscardstealer malware.

######	Features related to powershell code injectors. Our Sandbox checks if the tested file:
-	is a powershell malware of powerfun type;
-	is a powershell malware powerworm type;
-	attempts to create a suspicious powershell process;
-	attempts to create log entries via powershell scripts.

######	Features related to processes. Checks if the tested file:
-	is interested in some specific process in execution;
-	repeatedly searches for a process not found;
-	tries to fail some process.

######	Features related to ransomwares, cyber-attacks that turn the computer data inaccessible, requiring payment in order to restore the user access. Our Sandbox verifies that the audited server tries to:
-	create mutexes of ransomware named chanitor;
-	execute commands in bcdedit (command-line tool that manages boot configuration data) related to ransomware;
-	add extensions of files known to be ransomwares related to files that have been encrypted;
-	perform drives on files, which may be indicative of the data encryption process seen in an ransomware attack;
-	create instructions on how to reverse encryption made in an ransomware attack or attempt to generate a key file;
-	write a rescue message to disk, probably associated with an ransomware attack;
-	empty the trash;
-	remove or disable shadow copy, which is intended to speed up data restoration in order to avoid system recovery.

######	Features related to the use of sandboxes. The digital forensics examines if the tested file tries to:
-	detect if the sandboxes: Cuckoo, Joe, Anubis, Sunbelt, ThreatTrack/GFI/CW or Fortinet are being used, through the presence of own files used by them;
-	search for known directories where a sandbox can run samples;
-	check if any human activity is being performed;
-	discover the waiting time of Windows in order to determine the total time of Windows activity;
-	install a procedure that monitors mouse events;
-	disconnect or restart the system to bypass the sandbox;
-	delay analysis tasks;
-	shut down Windows functions monitored by the cuckoo sandbox.

######	Features related to Trojans (malicious program that enters a computer masked as another program, legitimate) of remote access, or RAT (Remote Access Trojans). Our Sandbox verifies if the tested server tries to create files, registry keys, and/or mutexes related to RATs: 
- Adzok, bandook, beastdoor, beebus, bifrose, blackhole/schwarzesonne, blackice, blackshades, bladabindi, bottilda, bozokrat, buzus, comrat, cybergate, darkcloud, darkshell, delf trojan, dibik/shark, evilbot, farfli, fexel, flystudio, fynloski/darkcomet, ghostbot, hesperbot, hkit backdoor, hupigon, icepoint, jewdo backdoor, jorik trojan, karakum/saharabot, koutodoor, aspxor/kuluoz, likseput, madness, madness, magania, minerbot, mybot, naid backdoor, nakbot, netobserve spyware, netshadow, netwire, nitol/servstart, njrat, pasta trojan, pcclient, plugx, poebot/zorenium, poison ivy, pincav/qakbot, rbot, renos trojan, sadbot, senna spy, shadowbot, siggen, spynet, spyrecorder, staser, swrort, travnet, tr0gbot bifrose, turkojan, urlspy, urx botnet, vertexnet, wakbot, xtreme, zegost.

######	Features related to the banking threats (Trojan horses):

-	Find out if the test file tries to create registry keys, Mutexes or Trojan files, and / or try to contact HTTP servers of the known threats. Banking Banking, Banking, Prinyalka Banking, SpyEye, Tinba Banking, Zeus, Zeus P2P, Dridex, Emotet and Online Banking.

######	Features related to payload in network. Checks if the server tested tries to:
-	verify if the network activity contains more than one unique useragent;
-	create Remote Desktop Connection Protocol (RDP) mutexes;
-	check the presence of mIRC chat clients;
-	install Tor (the onion router, open source software with the ability to securely and anonymously create online connections in order to safeguard the user's right to privacy), or a hidden Tor service on the machine;
-	connect to a Chinese URL shorter with malicious history;
-	create mutexes related to remote administration tools VNC (Virtual Remote Computer).

######	Features associated with network traffic hint windows 7 OS in PCAP format. Audit if suspicious document attempts to:
-	connect with an IP which is not responding to requests;
-	resolve a suspicious top domain;
-	start listening (socket) with some server;
-	connect to some dynamic DNS domain;
-	make HTTP requests;
-	generate ICMP traffic;
-	connect to some IRC server (possibly part of some BotNet);
-	make SMTP requests (possibly sending SPAM);
-	connect to some hidden TOR service through a TOR gateway;
-	start the wscript.exe file, which can indicate a payload download-based script (package body);
-	generate IDS or IPS alerts with Snort and Suricata (network monitoring and management tools).

######	Features related to DNS servers (Domain Name System, servers responsible for the translation of URL addresses in IP). It is investigated the audited file tries to:
-	connect to DNS servers of dynamic DNS providers;
-	connect to the expired malicious site 3322.org, or its related domain, 125.77.199.30;
-	resolve some Free Hosting domain, possibly malicious.

######	Features related to file type.

-	It is audited if the suspect server the suspect file is a SSH, Telnet, SCP and / or FTP-style FTP client with its files, registry keys and mutexes;
-	It is investigated whether the suspect file is a suspect downloader (download manager);
-	It is investigated if the file has in it a path to a pdb extension file, which contains information given directly to the system compiler.

######	Features related to antivirus. Checks if the file being investigated tries to:

-	check for registry keys, in regedit, for Chinese antivirus.

######	Features related to malware. Checks whether the audited file tries to:

-	create Mutexes (single name files, with a function to set a lock / unlock state, which ensures that only one process at a time uses the resources);
-	create Advanced Persistent Threat (APT) files, or connect to IP addresses and URLs of known threats: Carbunak/Anunak, CloudAtlas, Flame, Inception, Panda Putter, Sandworm, Turla Carbon and Turla/Uroboros.

######	Features related to Backdoors:

-	It is audited if the suspect file tries to create Backdoor files, registry keys or Mutexes of the known threats LolBot, SDBot, TDSS, Vanbot and Schwarzesonne.

######	Features related to bots (machines that perform automatic network tasks, malicious or not, without the knowledge of their owners):

-	It is audited if the suspect file tries to contact HTTP servers and / or tries to create Mutexes associated with Athena, Beta, DirtJumper, Drive2, Kelihos, Kotver, Madness, Pony, Ruskill, Solar, VNLoader, and Warbot Bots.

######	Features related to browsers. Checks if the suspect file tries to:

-	install a Browser Helper object (usually a DLL file that adds new functions to the browser) in order to let the navigation experience be impaired in some way;
-	modify browser security settings;
-	modify the browser home page;
-	acquire private information from locally installed internet browsers.

######	Features related to Bitcoin:

-	It is examined if the suspect file attempts to install the OpenCL library, Bitcoins mining tool.

######	Features related to Ransomware (type of malware that by means of encryption, leaves the victim's files unusable, then request a redemption in exchange for the normal use later of the user's files, a redemption usually paid in a non-traceable way, such as bitcoins) .

-	It is monitored if the suspect file tries to show, generate, or is an hta file (HTML Application), common extension type in situations involving ransomware.

######	Features related to exploit-related features which constitute malware attempting to exploit known or unackaged vulnerabilities, faults or defects in the system or one or more of its components in order to cause unforeseen instabilities and behavior on both your hardware and in your software. The proposed digital forensic verifies whether the audited file attempts to:

-	contact the HTTP server of the Blackhole Exploit Kit (a threat that had its peak of performance in 2012, aims to download malicious content on the victim's computer);
-	create mutexes of the Sweet Orange EK exploit;
-	create mutexes from other known exploits;
-	use the technique known as heapspray, where memory is completely filled, causing the computer to experience crashes.

######	Features related to Infostealers, malicious programs that collect confidential information from the affected computer. Digital forensics checks if suspicious file tries to:

-	create files related to infostealer Derusbi;
-	collect credentials and software information from locally installed FTP clients;
-	collect information and credentials related to locally installed Instant Messenger clients;
-	create a program that monitors keyboard inputs (possibly a keylogger);
-	collect credentials and information from locally installed e-mail clients.


######	Features related to virtual machines. The goal is to verify that the audited file searches for:

-	detect whether Bochs, Sandboxie, VirtualBox, VirtualPC, VMware, Xen or Parallels virtual machines are being used through the presence of registry keys (regedit), files, instructions, and device drivers used by them;
-	find the computer name;
-	find the disk size and other information about the disk, which may indicate the use of a virtual machine with small and fixed disk size, or dynamic allocation;
-	discover the BIOS version, which may indicate virtualization;
-	discover the CPU name in the registry, which may indicate virtualization;
-	detect a virtual machine through the firmware;
-	detect the presence of IDE drives in the registry, which may indicate virtualization;
-	detect the presence of SCSI disks;
-	enumerate services, which may indicate virtualization;
-	detect Hyper-V through registry keys (regedit);
-	check the amount of memory in the system in order to detect virtual machines with little available memory;
-	check adapter addresses that can be used to detect virtual network interfaces;
-	detect a virtual machine by using pseudo devices (parts of the kernel that act as device drivers but do not actually match any hardware present on the machine);
-	detect whether it is running in a window, indicative of VirtualBox usage.

######	Features related to Firewall. The proposed digital forensics audits if the file tries to:

-	modify local firewall policies and settings.

######	Features related to cloud computing. The file is audited when you try to:

-	connect to storage services and / or files from Dropbox, Google, MediaFire, MegaUpload, RapidShare, Cloudflare and Wetransfer.

######	Features related to DDoS (Dynamic Danial of Service) attacks:

-	It is audited if the suspect file create mutexes, other files and bots known as DDoS of the IPKiller, Dark-DDoS, Eclipse and Blackrev types.

######	Features related to Infostealers, malicious programs that collect confidential information from the affected computer. Digital forensics checks if suspicious file tries to:

-	create files related to infostealer Derusbi;
-	collect credentials and software information from locally installed FTP clients;
-	collect information and credentials related to locally installed Instant Messenger clients;
-	create a program that monitors keyboard inputs (possibly a keylogger);
-	collect credentials and information from locally installed e-mail clients.
