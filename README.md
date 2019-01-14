# REJAFADA
(Retrieval of Jar Files Applied to Dynamic Analysis)

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

In relation to virtual plagues, REJAFADA extracted malicious Jar files from VirusShare which is a repository of malware samples to provide security researchers, incident responders, forensic analysts, and the morbidly curious access to samples of live malicious code. With respect to benign Jar files, the catalog was given from application repositories such as Java2s.com, and findjar.com. All of the benign files have been audited by VirusTotal. Then, the benign Jar files, contained in REJAFADA, had their benevolence attested by the main commercial antiviruses of the world. The obtained results corresponding to the analyses of the benign and malware Jar files, resulting from the VirusTotal audit, are available for consultation at the virtual address of REJAFADA.

The goal of creation of REJAFADA dataset is to give full possibility of the proposed methodology being replicated by third parties in future works. Then, REJAFADA makes available, freely, of all their samples such as benign as malwares:

• VirusTotal audits;

• Dynamic analysis of Cuckoo Sandbox.

REJAFADA also makes available in its virtual address, its 998 benign Jar files. In addition, our dataset displays the list of all other 998 Jar files, this time, malwares. Then, there is the possibility of the acquisition of all the malwares, employed by REJAFADA, through the agreement establishment and submission to the rules of use of ViruShare. It is concluded that our REJAFADA dataset enables transparency and impartiality to the research, in addition to demonstrating the veracity of the achieved results. Therefore, it is expected that REJAFADA serves as base for the creation of new scientific works aiming NGAVs.
