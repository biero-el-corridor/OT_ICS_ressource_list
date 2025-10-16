# OT_Resource_List

Welcome to our collaborative OT/ICS Resource List Repository. This space is dedicated to assembling a wide range of resources that cover everything from foundational learning materials to sophisticated tools and datasets for those involved in Operational Technology and Industrial Control Systems cybersecurity. By pooling knowledge from various sources, we aim to foster a learning and working environment that encourages sharing and growth. Each entry in this repository has been selected for its relevance and utility in addressing the unique challenges of OT cybersecurity. We invite you to explore, contribute, and help us keep this resource vibrant and current for the global cybersecurity community.


Collaboration based OT resource list, gathered through research and internet adventures.

The purpose of this wiki is basically to cover a large sprectrum of Cybersecurity for the OT field, from training to simple definitions of the technical knowledge.

## Information

If you are here to search for resources and mass information on different protocols and concepts, I advise you to go directly to the sections [ICS ressource collection](#ics_ressource_collections), [ICS Lab Setup](#ics-lab-setup), and [ICS news outlet](#ics_news_outlet).

The rest is just a compilation of my own research. If you are interested, an HTML bookmark file, usable on Firefox, is available.

## Sections:

- [Information](#information)

- [Sections:](#sections)
  - [ICS challenge](#ics-challenge)
  - [ICS CERT and CTI](#ics-cert-and-cti)
      - [ICS Cyber Treath Inteligence repport](#ics-cti)
      - [ICS CERT](#ics-cert)
  - [ICS OSINT](#ics-osint)
    - [public ip browser](#public-ip-browser)
    - [IP browser api automations tool](#ip-browser-api-automations-tool)
    - [ICS honeypot detection](#ics-honeypot-detection)
  - [ICS Ressource collections](#ics-ressource-collections)
  - [ICS Protocol , pcap and dataset](#ics-protocol-pcap-and-dataset)
    - [ICS Protocol](#ics-protocol)
    - [ICS protocol parameter](#ics-protocol-parameter)
    - [ICS Pcap's coletions](#ics-pcap-collections)
    - [ICS Dataset](#ics-dataset)
  - [ICS Security paper and conference](#ics-security-paper-and-conference)
  - [ICS Firmware Tool And PLC Emulator](#ics-tool-firmware-and-plc-emulator)
    - [ICS Tools](#ics-tools)
    - [ICS PLC and Protocol Emulator](#ics-plc-and-protocol-emulator)
    - [ICS Firmware](#ics-firmware)
  - [ICS Lab Setup](#ics-lab-setup)
    - [ICS Lab Setup](#ics-lab-setup)
  - [ICS Outlet, article and books](#ics-outlet-article-and-books)
    - [ICS news outlet](#ics-news-outlet)
    - [ICS news articles](#ics-news-article)
    - [ICS books](#ics-books)
  - [Forum](#ics_forum)
  - [Hardware](#hardware)
    - [Hardware Materials and Emulator](#hardware-materials-and-emulator)
    - [Hardware hacking tutorial](#hardware-hacking-tutorials)
    - [Datasheet database](#datasheet-database)
    - [Integrated Compoment info browser](#integrated-compoment-info-browser)
  - [ISC security training](#ics-training)
  - [ICS Law Requirement-guide and Standart](#ics-law-requirement-guide-and-standart)
    - [PCA PRA and Risk management](#pca-pra-risk-management)
    - [ICS Requirement guide](#ics-requirement-guide)
    - [ICS Law and Act](#ics-law-and-act)
    - [ICS Group,  Alliance and committee](#ics-group-alliance-and-committee)
  - [ICS Vendor and equipement](#ics-vendor-and-equipement)
    - [ICS security Equipement](#ics-security-equipement)
    - [ICS security Vendor](#ics-security-vendor)
  - [ICS Blue Team](#ics-blue-team)
    - [ICS Forensic](#ics-forensic)
    - [ICS SOC](#ics-soc)
      - [ICS Rules](#ics-rules)
 - [ICS Exploit Pentest & Red Team](#ics-exploit-pentest--red-team)
---

# ICS challenge

| Title | Description |
| ----- | ----------- |
| [Labtainer Lab Summary - Center for Cybersecurity and Cyber Operations - Naval Postgraduate School](https://nps.edu/web/c3o/labtainer-lab-summary1) | Fully packaged Linux-based computer science lab exercises with an initial emphasis on cybersecurity. |
| [SANS Dragos CTF 2023 Event](https://ranges.io/event/345c592a-e5d5-11ed-8ea9-613263343732/players) | This free ICS CTF will feature multiple challenges focused on analyzing logic files, logs, network traffic, ICS protocols, digital forensic artifacts, and more to analyze attacks against an in-depth ICS range. |
| [Play Now with BOTS Partner Experiences: Dragos Splunk](https://www.splunk.com/en_us/blog/security/play-now-with-bots-partner-experiences-dragos1.html) | Helps you quickly prioritize, investigate, and respond to industrial threats which can also help compliance requirements across both IT and OT environments. |
| [WRITE UP: Color Plant 1+2 (Misc) - FCSC2022](https://github.com/themaskott/fcsc_2022/tree/main/misc/color_plant) | (FR) A FCSC Challenge in 2022 about a web interface for monitoring the industrial system |
| [Hack a Sat challenge](https://hackasat.com/) | A fun challenge that bridges the cybersecurity aficionados and space program lovers |
| [Red Alert ICS CTF](https://forum.defcon.org/node/249872) | One of the ICS themed CTF of the DefCon conference|
| [Biero el corridor brutal tank challenge](https://github.com/biero-el-corridor/Talk_Workshop_and_Chall_creation/tree/main/Challenge/Brutal_Tank) | Challenge created for cyberdefender , you can play it localy via this repository |
| [Hackropol ICS related challenge](https://hackropole.fr/fr/industrial-protocol/) | Hackropole and the FCSC database, here are all the challenges related to the industrial control system that the FCSC has proposed since its creation.|
| [Ace Responder ICS challenge: under pressure](https://www.aceresponder.com/challenge/under-pressure) |Ace Responder is a blue team training platform, this is their OCS related DFIR challenge.|
| [DFRWS 2023 Challenge on Industrial Control System Forensics](https://dfrws.org/dfrws-2023-challenge/) ||
| [github repository for the the above link ](https://github.com/dfrws/dfrws2023-challenge) | DFRWS 2023 Challenge on Industrial Control System Forensics github repos|

---

# ICS CERT and CTI

## ICS CTI

| Title | Description |
| ----- | ----------- |
| [Dragos 2018 repport](https://www.dragos.com/wp-content/uploads/Industrial-Control-Threat-Intelligence-Whitepaper.pdf)|Dragos is a ICS CTI compagnie , every year theyr make a repport, this is for the year 2023|
| [Dragos 2023 repport](https://sekuro.io/wp-content/uploads/2024/05/OT-Cybersecurity-The-2023-Year-In-Review.pdf)|Dragos is a ICS CTI compagnie , every year theyr make a repport, this is for the year 2023|
| [Dragos 2024 repport](https://hub.dragos.com/hubfs/312-Year-in-Review/2025/Dragos-2025-OT-Cybersecurity-Report-A-Year-in-Review.pdf?hsLang=en)|Dragos is a ICS CTI compagnie , every year theyr make a repport, this is for the year 2024 |
| [Claroty IOControl repport](https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol)| claroty analyse of IOcontrol mallware|
| [Mandiant sandworm article](https://cloud.google.com/blog/topics/threat-intelligence/sandworm-disrupts-power-ukraine-operational-technology/?hl=en)| Sandworm Disrupts Power in Ukraine Using a Novel Attack Against Operational Technology |
| [CISA Report CCP APT TTP's on ICS](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a)|People's Republic of China State-Sponsored Cyber Actor Living off the Land to Evade Detection|
|[ICS threath inteligence manual](https://www.dragos.com/wp-content/uploads/Industrial-Control-Threat-Intelligence-Whitepaper.pdf)|Industrial Control Threat Intelligence |
| [waterfall security 2025 OT Cyber Security Threat Report](https://waterfall-security.com/wp-content/uploads/2025/03/2025-OT-Cyber-Security-Threat-Report.pdf) | waterfall security 2025 OT Cyber Security Threat Report |
| [Mandiant sandworm report ](https://cloud.google.com/blog/topics/threat-intelligence/sandworm-disrupts-power-ukraine-operational-technology/?hl=en) | Sandworm Disrupts Power in Ukraine Using a Novel Attack Against Operational Technology |
| [IOC/TTP on China-nexus campain](https://otx.alienvault.com/pulse/6825846637a467872cdf202b) |IOC&TTP - China-Nexus Nation State Actors Exploit SAP NetWeaver|
| [Report on China-nexus actions](https://blog.eclecticiq.com/china-nexus-nation-state-actors-exploit-sap-netweaver-cve-2025-31324-to-target-critical-infrastructures) |China-Nexus Nation State Actors Exploit SAP NetWeaver (CVE-2025-31324) to Target Critical Infrastructures|


---

## ICS CERT
| Title | Description |
| ----- | ----------- |
| [CERT Siemens](https://new.siemens.com/global/en/products/services/cert.html) | Siemens ProductCERT and Siemens CERT |
| [CERT ABB Group](https://global.abb/group/en/technology/cyber-security/alerts-and-notifications) | ABB CERT and alert services |     
| [CERT Schneider](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) | Cybersecurity support portal of Schneider CERT |     
| [Dragos CVE disclosure](https://www.dragos.com/advisories/) | Dragos CVE Discosure  |



---
# ICS OSINT

## Public IP browser
| Title | Description |
| ----- | ----------- |
| [Hunto IP browser](https://hunter.how/) | Chinese Shodan-like IP browser |
| [FOFA IP brower](https://en.fofa.info/) | Little browser of Shodan|
| [Shodan](https://www.shodan.io/) | Best search engine for IoT I guess |
| [Zoomeye](https://www.zoomeye.org/) | Best IP search engine on the east side of the world |
| [Censys](https://search.censys.io/) | Yet Another Shodan browser-like |
| [Onyphe](https://www.onyphe.io/) | French shodan like , that is really interesting|
| [quanxin](https://hunter.qianxin.com/) |Chniese IP Browser |
| [Shodan wreapper](https://shdn.io/) | shodan api wrapper with dns record direclty show|
| [Shadowservers world map of OT equipment 1](https://dashboard.shadowserver.org/statistics/iot-devices/map/) | Show the world statistics of IoT devices per country |


## IP browser API automation tool

| Title | Description |
| ----- | ----------- |
| [API base cli search for zoomeye](https://github.com/knownsec/Kunyu) | Cyberspace Search auxiliary tool |
| [API base cli search for FOFA](https://github.com/FofaInfo/Awesome-FOFA/blob/main/Get%20Started%20with%20FOFA/A%20Beginner%E2%80%98s%20Guide.md) | Search engine for mapping the cyberspace |
| [API base cli search for IP browser](https://github.com/xzajyjs/ThunderSearch) | (CH) Information collection tool for GUI interface developed by the official api of cyberspace search engine |
| [API base cli search for shodan and other](https://github.com/sdnewhop/grinder) | Python framework to automatically discover and enumerate hosts from different back-end systems (Shodan, Censys)  |

---
## ICS HONEYPOT DETECTION

| Title | Description |
| ----- | ----------- |
| [Honeydet conpot simens signature](https://github.com/referefref/honeydet/blob/d3a0a05799d5f7333dad9946d444c13d0440330e/signatures.yaml#L320) |honeydet is a signature based honeypot detector tool written in Golang |
| [Honeypot Cyber deceptions based paper](https://ceur-ws.org/Vol-3374/paper06.pdf) | Honeypot and cyber deception as a tool for detecting cyber attacks on critical infrastructure |
| [ICSRANK](https://www.icsrank.com/) | Query for search ICS equipent on public ip browser |
| [biero-el-corridor honepot detections nuclei template](https://github.com/biero-el-corridor/ICS_CPS_nuclei_template/tree/main/template/Honeypot_detection)|template to uwe with nuclei to detec defined honeypot (snap7 & Ethnernet/IP_CIP base)|
| [ICS Honeypot System (CamouflageNet) Based on Attacker's Human Factors - ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2351978915001766) | ICS Honeypot System (2015) |

---
## ICS Ressource collections

| Title | Description |
| ----- | ----------- |
| [Resource collections for beginners](http://www.robertmlee.org/a-collection-of-resources-for-getting-started-in-icsscada-cybersecurity/) | Security-oriented list of resources about industrial network protocols  |  
| [ICSCSI - Library of Resources for Industrial Control System Cyber Security](https://icscsi.org/library/index.html) | Library of Resources for Industrial Control System Cyber Security |
| [MITRE ICS matrix](https://attack.mitre.org/matrices/ics/) | TTP MITRE matrix schemes for ICS |
| [Orange-Cyberdefense/awesome-industrial-protocols](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols) | Compilation of industrial network protocols resources focusing on offensive security |
| [Github star ressource list on ICS](https://github.com/stars/berensn/lists/iot-ics) | Github ressource list of star from berensn | 
| [MrM8BRH GitHub user resource list](https://github.com/MrM8BRH/CRLJ/blob/main/Red%20Team%20%26%20Penetration%20Testing/ICS%20%26%20SCADA.md) | A smaller version of this github, but not made by myself |
| [Biero OT/ICS Resource list](https://www.youtube.com/watch?v=dQw4w9WgXcQ&ab_channel=RickAstley) | Refresh button, but I had to put it there at some point. |
| [Industrial Automation Abbreviation  Acronyms – PLC Tutorial Point](https://www.plctutorialpoint.com/industrial-automation-abbreviation-acronyms/) | Wiki of abbreviations - good if, like myself, you hate acronyms because it goes messy if you're versatile |
| [Major PLC manufacturers and PLC Software’s List – PLC Tutorial Point](https://www.plctutorialpoint.com/major-plc-manufacturers-and-plc-softwares-list/) | List of the major PLC manufacturers & softwares |


---
# ICS Protocol Pcap and Dataset

## ICS Protocol

| Title | Description |
| ----- | ----------- |
| [IEC 61131-3 - Wikipedia](https://en.wikipedia.org/wiki/IEC_61131-3) | International Standard for programmmable logic controllers - Main focus here on PLCs (Feel free to check out the other IECs) |
| [TCF - Eclipsepedia](https://wiki.eclipse.org/TCF) | Target Communication Framework Documentation |
| [ascolab GmbH](https://www.ascolab.com/index.php) | Lab for industrial communication documentation |
| [Wireshark Foundation / wireshark · GitLab](https://gitlab.com/wireshark/wireshark/-/tree/master/plugins/epan/opcua) | Come on guys, do we have to tell you what is wireshark ? Haha |
| [BACnet stack - open source BACnet protocol stack](https://bacnet.sourceforge.net/) | BACnet app layer, network layer and MAC layer communication services |
| [Official page for programming parameters of snap 7 on the LOGO! 8](https://snap7.sourceforge.net/logo.html) | Documentation for LOGO! implementation settings |
| [Allen-Bradley Reference Manual for Ethernet](https://literature.rockwellautomation.com/idc/groups/literature/documents/rm/enet-rm002_-en-p.pdf) |Allen-Bradley Reference Manual for Ethernet|
| [Current list of all used apps with OPC UA compliance](https://opcfoundation.org/products/) | OPC Servers, clients, toolkits and services from members of the OPC Foundation |

## ICS Protocol Parameter

| Title | Description |
| ----- | ----------- |
| [Modbus basic Functions code dcumentation](https://ozeki.hu/p_5846-appendix.html) |Modbus basic Functions code dcumentation|
| [BACnet Vendor ID](https://bacnet.org/assigned-vendor-ids/) | BACnet offical Assigned Vendor IDs| 

## ICS Pcap collections

| Title | Description |
| ----- | ----------- |
| [PCAP Archive ICS Defense](https://icsdefense.net/pcap) | Collection of PCAPs for ICS Defense |
| [Traffic captures between STEP7 WinCC and S7-300/S7-400 PLCs](https://github.com/gymgit/s7-pcaps) | Some Snap7-PCAPs for clients applications, s7-300 and s7-400 series PLCs from a pretty cool dude |    
| [Cloudshark modbus bcap](https://www.cloudshark.org/captures/3bfef9452c76) | online pcap containng modbus and ICP protocol|
| [Pcap collections from netresec](https://www.netresec.com/?page=PcapFiles) | Pcap collections from netresec, the guy who make and maintain networkminer |

## ICS Dataset

| Title | Description |
| ----- | ----------- |
| [OPC UA DARASET](https://paperswithcode.com/dataset/dataset-to-easing-the-conscience-with-opc-ua) | Dataset to "Easing the Conscience with OPC UA: An Internet-Wide Study on Insecure Deployments"  |
| [Electra dataset, aggregations of multiple big PCAP](http://perception.inf.um.es/ICS-datasets/) | Anomaly detection ICS dataset from Electra dataset |      
| [OPC UA DATASET](https://digi2-feup.github.io/OPCUADataset/) |The OPC UA CSV source file can be downloaded here. You can also find it in the IEEE DataPort.The generation of the dataset containing OPC UA traffic was possible due to the setup and execution of a laboratory CPPS testbed. This CPPS uses OPC UA standard for horizontal and vertical communications. Regarding the CPPS testbed setup, it consists on seven nodes in the network, as represented in the next Figure. |

---
# ICS Security paper and conference

| Title | Description |
| ----- | ----------- |
| [The Spear To Break The Security Wall Of S7CommPlus](https://www.blackhat.com/docs/eu-17/materials/eu-17-Lei-The-Spear-To-Break%20-The-Security-Wall-Of-S7CommPlus-wp.pdf) | Exploit Explanation of S7CommPlus and some security measures to counter it |
| [Europe's 2022 Energy Sector: the Cyber Threats landscape - Citalid](https://citalid.com/europes-2022-energy-sector-the-cyber-threats-landscape/) | Cyber threat Landscape of 2022 for the Energy Sector |
| [SANS ICS Security - Control Systems Are a Target.pdf](https://sansorg.egnyte.com/dl/eQu4hT5fCW) | 3-slide presentation of SANS on ICS/SCADA Security. Pretty cool for education. |
| [Principles of Information Security, 5th ed. - Principles of Information Security (PDFDrive)](http://www.mim.ac.mw/books/Principles%20of%20Information%20Security%20(%20PDFDrive%20).pdf) | [Down for the moment - Use to be a bible of Cybersec] |
| [Industrial Control System Security - Top 10 Threats and Countermeasures 2016](https://www.hannovermesse.de/apollo/hannover_messe_2021/obs/Binary/A1087894/Top-10-ICS-Threats_and_Countermeasures.pdf) | BSI publication on OWASP Top 10 like but for ICS Security (2019) |
| [CCE-Phase-1-4-Reference-Document.pdf](https://inl.gov/wp-content/uploads/2021/01/CCE-Phase-1-4-Reference-Document.pdf) | [Down for the moment] |
| [DEF CON 26 - Thiago Alves - Hacking PLCs and Causing Havoc on Critical Infrastructures - YouTube](https://www.youtube.com/watch?v=-KHel7SyXsU&ab_channel=DEFCONConference) | 40mn-conference on Hacking PLCs with OpenPLC |
| [Reverse of a Schneider network protocol by Biero Llagas - Medium](https://medium.com/@biero-llagas/reverse-of-a-schneider-network-protocol-1e94980faa57) | A medium article on the UMAS schneider compliant protocol from a pretty cool dude |
| [Grehack - Paper - Industrial Control Systems Dynamic Code Injection.pdf](https://grehack.fr/data/grehack2015/paper/Grehack%202015%20-%20Paper%20-%20Industrial%20Control%20Systems%20Dynamic%20Code%20Injection.pdf) | [Down for the moment - Used to be a write-up on a ICS chall] |
| [AMNESIA:33 How TCP/IP Stacks Breed Critical Vulnerabilities in IoT, OT and IT Devices](https://www.forescout.com/resources/amnesia33-how-tcp-ip-stacks-breed-critical-vulnerabilities-in-iot-ot-and-it-devices/) | AMNESIA is a study of the Project Memoria on the results of the security analysis of seven open source TCP/IP stacks and a bundle of 33 vulnerabilities used on major IoT, OT and IT device vendors |
| [VIRTUAL PLC PLATFORM FOR SECURITY AND FORENSICS OF INDUSTRIAL CONTROL SYSTEMS](https://scholarscompass.vcu.edu/cgi/viewcontent.cgi?article=8604&context=etd) | 2023 research paper on virtual PLC platform for security and forensics of industrial control systems |
| [Towards High-Interaction Virtual ICS Honeypots-in-a-Box](https://tippenhauer.de/publication/antonioli-16-towards/antonioli-16-towards.pdf) | Research Paper on the design of virtual, high-interaction and server-based ICS honeypot and the deployment of a realistic, cost-effectibe and maintainable ICS honeypots. |
| [Pwn2Own Miami 2022: OPC UA .NET Standard Trusted Application Check Bypass](https://sector7.computest.nl/post/2022-07-opc-ua-net-standard-trusted-application-check-bypass/) | 1st part of a series of write-up about ICS vulnerabilities. This one is about the Trusted Application Check Bypass in the OPC UA .NET Standard (CVE-2022-29865) |
| [Siemens Trust Center PKI](https://assets.new.siemens.com/siemens/assets/api/uuid:2aa471ee-28c2-42f0-9df8-f7bc6e5e658d/siemens-pki-ca-policy-2020.pdf) | Documentation on the Siemens Certification Authority Hierarchy of 2020 |
| [HTB ICS network segmentation](https://www.hackthebox.com/blog/ics-network-segmentation) |Learn about the Purdue Model of ICS network segmentation from Hack The Box's ICS expert Barry "8balla" Murrell. |
| [CVE-2019-12480 article releated](https://1modm.github.io/CVE-2019-12480.html) | article on how they have  discover the vulnerability (spoiler by fuzzing)  |
| [Article by forescout](https://www.forescout.com/blog/analysis-of-energy-sector-cyberattacks-in-denmark-and-ukraine/) | Clearing the Fog of War – A critical analysis of recent energy sector cyberattacks in Denmark and Ukraine  |
| [Paper on PLC attack detections and forensic](https://www.mdpi.com/2227-9717/11/3/918)| A Survey on Programmable Logic Controller Vulnerabilities, Attacks, Detections, and Forensics |
| [Compromising Industrial Processes using Web-Based Programmable Logic Controller Malware](https://www.ndss-symposium.org/wp-content/uploads/2024-49-paper.pdf) | 2024 Research Paper on how to compromise industrial processes using Web-based PLC Malware |
| [CWE Industrial Control System and Operational Technology Special Interest Group](https://github.com/CWE-CAPEC/ICS-OT_SIG) | While IT has an extant body of work related to identifying and classifying security weaknesses, IT and ICS/OT are different, and existing IT classifications are not always useful in describing and managing security weaknesses in ICS/OT systems. Addressing this gap will help all stakeholders communicate more efficiently and effectively and promote a unity of effort in identifying and mitigating ICS/OT security weaknesses, especially in critical infrastructure. |
| [Unpacking the Blackjack Group's Fuxnet Malware](https://claroty.com/team82/research/unpacking-the-blackjack-groups-fuxnet-malware) | Unpacking the Blackjack Group's Fuxnet Malware Ukrenian state sponsor attacking russian PLC|
| [bsides-ics-ot-tampa](https://www.blackhillsinfosec.com/event/bsides-ics-ot-tampa/) |Bside conference specialised in ICS/OT security|
| [Read description](https://homeland.house.gov/wp-content/uploads/2024/02/2024-02-06-CIP-HRG-Testimony.pdf) |securing operational technology:a deep dive into the water sectorhearingbefore thesubcommittee on cybersecurity and infrastructure protectionone hundred eighteenth congress|
| [From Pass-the-Hash to Code Execution on Schneider Electric M340 PLCs](https://i.blackhat.com/EU-24/Presentations/EU-24-Zaltzman-From-Pass-the-Hash-to-Code-Execution-wp.pdf) |Black hat 2024: From Pass-the-Hash to Code Execution on Schneider Electric M340 PLCs|
| [Exploring URGENT/11 Vulnerabilitie]() | Exploring and Exploiting Programmable Logic    Controllers with URGENT/11 Vulnerabilitie |
| [Armis report on VxWorks exploit used by Schneider & Rockwell](https://info.armis.com/rs/645-PDC-047/images/Armis-URGENT11-on-OT-WP.pdf) | Exploring and Exploiting Programmable Logic Controllers with URGENT/11 Vulnerabilities |

---
# ICS Tool Firmware And PLC Emulator

## ICS Tools

| Title | Description |
| ----- | ----------- |
| [FUXA](https://github.com/frangoteam/FUXA) | Web-based Process Visualization (SCADA/HMI/Dashboard) software |
| [ScadaBR - Portuguese](http://www.scadabr.com.br/) | SCADA system with applications in Process Control and Automation (opensource) (portuguese version) |
| [ScadaBR - French](https://www.automation-sense.com/blog/automatisme/le-logiciel-de-supervision-scada-open-source-scadabr.html) | SCADA system with applications in Process Control and Automation (opensource) (french version) | 
| [ScadaBR - English](https://sourceforge.net/p/scadabr/wiki/Manual%20ScadaBR%20English%200%20Summary/) | SCADA system with applications in Process Control and Automation (opensource) (english version) | 
| [ICSpector](https://github.com/microsoft/ics-forensics-tools) | Microsoft's ICS Forensics Framework for analyzing PLC metadata and project files. Useful for incident response and forensic investigations. |
| [ ICS Development Kits.](https://www.traeger.de/products/development) |Downloadable SDK for multiple Protocol (very cool) |

## ICS PLC and Protocol Emulator

| Title | Description |
| ----- | ----------- |
| [NetToPLCSim download SourceForge.net](https://sourceforge.net/projects/nettoplcsim/) | TCP/IP-Network extension for the PLC simulation software Siemens PLCSim (Step 7 V5.4/5.5) |
| [MHJ-Software EN - comdrvs7](https://www.mhj-tools.com/?page=comdrvs7) | All-in-one communication Library for S7-PLCs |
| [DNP3 OPC Server Configuration Guide](http://ioserver.com/dnp3.html) | Everything's in the title |
| [IOServer - Interface to multiple protocols through a single OPC Server](http://ioserver.com/index.html) | Software allowing OPC clients such as HMI and SCADA systems to exchange plant floor data with PLCs |
| [OpenPLC V3 - Docker Image Docker Hub](https://hub.docker.com/r/tuttas/openplc_v3) | A Docker Image based on Ubuntu 18.04 for the OpenPLC Server |
| [HoneyPLC: High-interaction Honeypot for PLCs and Industrial Control Systems](https://github.com/sefcom/honeyplc) | Github repository of HoneyPLC, designed to simulate multiple PLC models from different vendors |
| [Parallel DNP3 slave simulator](https://github.com/gec/dnp3slavesim) | Github repository for DNP3 Slave Simulator. Designed to be used for integration and performance testing of frent-end applications. |
| [DNP3, MODBUS, OPC Client & Server Simulator](https://icsprotocols.wordpress.com/download-free-trial-version/) | Link for Free Trial Version – Everything's in the title  |
| [OpenPLC Server - Docker Image Docker Hub](https://hub.docker.com/r/eflexsystems/openplc-server) | Docker containers for openplc server and editor |    
| [The World's Most Popular Allen-Bradley PLC Simulator](https://canadu.com/lp/logixpro.html) | A stand-alone PLC training system without the expense of a PLC |
| [Modifier Conpot of multiple ICS protocols](https://hub.docker.com/u/raconpot) | Modifier Conpots on dockerhub - with docker images from 2021, with 15 repositories |
| [snap7 dockerfile](https://hub.docker.com/r/gijzelaerr/snap7/dockerfile) | Docker containing S7-comm protocol capabilities via snap7 lib|
| [Rapid SCADA website](https://rapidscada.org/) | Rapid SCADA is an open source industrial automation platform. The out of the box software provides tools for rapid creation of monitoring and control systems. In case of large implementation, Rapid SCADA is used as a core for development of custom SCADA and MES solutions for a Customer.  |
| [EcoStruxure Control Expert V15.3 installation file.](https://www.se.com/us/en/download/document/EcoStruxureControlExpert-V15.3/) | Free trialversion of EcoStruxure Control Expert |

## ICS Firmware

| Title | Description |
| ----- | ----------- |
| [Siemens LOGO! firware archive](https://support.industry.siemens.com/cs/document/109812710/firmware-update-v1-83-02-for-logo!-8-3-basic-devices?dti=0&lc=en-FR) |Siemens LOGO! firware archive|
|[Siemens LOGO firmware download page](https://support.industry.siemens.com/cs/document/109812710/firmware-update-v1-83-02-for-logo!-8-3-basic-devices?dti=0&lc=en-FR) | siemens website , siemens LOGO PLC  firmware download page |

---
# ICS Lab Setup

## ICS Lab Setup

| Title | Description |
| ----- | ----------- |
| [Power_Grid_Simulation_System_Document](https://github.com/LiuYuancheng/Power_Grid_Simulation_System_Document) | The Mini OT Power Grid Simulation System is a digital equivalent software platform designed to simulate the core operations of a hybrid power grid system, including hybrid power generation (natural gas power plants, solar power plants, and wind turbine farms), high-voltage power transmission and a three-level step-down power distribution system. The simulation integrates a SCADA system that incorporates PLCs for remote system control, RTUs and MUs for real-time data monitoring, and an HMI interface for operators to manage the grid. |
| [LiuYuancheng Hight interactions Honeypot](https://github.com/LiuYuancheng/Py_PLC_Honey_Pot) | This project aims to develop a sophisticated honeypot system that emulates an OT (Operational Technology) SCADA network environment, bridging Level 1 OT field controller devices.  |
| [How to connect Open PLC with Factory I/O - YouTube](https://www.youtube.com/watch?v=9N6YaS3BqLM&list=PLb-0ok9BPLj4kNVPOq5jPVxdnheWG-Aex&ab_channel=seafoxc) | A 20mn video tutorial on how to connect OpenPLC with Factory I/O |
| [Virtual Industrial Cybersecurity Lab archivos - Rodrigo Cantera](https://rodrigocantera.com/en/category/virtual-industrial-cybersecurity-lab/) | A tutorial on how to develop and implement a TCP sequence prediction attack to inject malicious Modbus TCP packets with Scapy |
| [How to set up an OT analysis lab.  by biero llagas  Medium](https://medium.com/@biero-llagas/how-to-set-up-an-ot-analysis-lab-351a111ab33e) | A Medium article on how to set up an OT analysis lab on the S7comm protocol made by a cool dude |  
| [stunnel](https://www.stunnel.org/) |Stunnel is a proxy designed to add TLS encryption functionality to existing clients and servers without any changes in the programs' code.|
| [ICS PCAP Viz](https://github.com/cutaway-security/ICSPcapViz) | A packet capture visualizer designed for industrial control networks, assisting in network traffic analysis and anomaly detection. |
| [Python Virtual PLC Simulator with IEC-60870-5-104 Communication Protocol ](https://www.linkedin.com/pulse/python-virtual-plc-simulator-iec-60870-5-104-protocol-yuancheng-liu-bov7c/?trackingId=4Ge4VLj3cFhFjGCy%2Bw32fA%3D%3D) |self explanatory|
| [Simulating Simple Railway Station Train Dock and Depart Auto-Control System with IEC104 PLC Simulator](https://www.linkedin.com/pulse/simulating-simple-railway-station-train-dock-depart-auto-control-liu-vsscc/?trackingId=ytxH9nNTsAAy%2FJ11Dhl8Jw%3D%3D) |self explanatory|
| [Lab setup of a Schenider electric ecosystem](https://medium.com/@biero-llagas/lab-setup-notice-non-uniformity-for-authentication-system-security-modicon-emulator-on-1a0b743cb386) |Lab setup || Notice non-uniformity for authentication system security: modicon emulator on Schneider electric Controle expert Classique (Part1).|


---
# ICS Outlet Article and Books

## ICS news outlet

| Title | Description |
| ----- | ----------- |
| [Scadafence blog panel](https://blog.scadafence.com/) | A SCADA-focused defence blog. Very interesting, I recommend it. |      
| [The Only SCADAhacker blog](https://scadahacker.com/) | A blog that provides a single point of contact for a wide range of readers covering multiple industry segments for quitely everything related to industrial security |
| [Ruscadasec telegram](https://t.me/s/ruscadasecnews) | Russian SCADA news telegram   |
| [Iranian ICS news telegram](https://t.me/s/mohandesmaher) | Iranian/Persian telegram ICS-related news  |
| [Article about offensive onsint on OT equipement?](https://www.offensiveosint.io/) |Offensive OSINT s01e04 - Intelligence gathering on critical infrastructure in Southeast Asia |
| [Offensive OSINT blog news](https://www.offensiveosint.io/) |From the creator of KAMERKA |
| [Good old Hackernews](https://thehackernews.com/) | Well, it's Good'ol Hackernews mi friend ! |
| [Securityweek news OT/ICS sections](https://www.securityweek.com/category/ics-ot/) |Securityweek news OT/ICS sections |
| [Security affair](https://securityaffairs.com/tag/plc) | Nothing related to your supervisory officer having extramarital activities, it's a Threat Intelligence source of information |
| [Japanese cyber ICS/OT news](https://iototsecnews.jp/) | Threat Intel source of info, but it's japanese |
| [FBI Internet Crime Complaint Center (IC3)](https://www.ic3.gov/Home/IndustryAlerts) | Everything's in the title |
| [Centralised podcast themed ICS](https://www.listennotes.com/playlists/beerisac-otics-security-podcast-playlist-j-G0QwC8Zsu/episodes/) | A list of ICS themed podcast |
| [Industrial Cyber news outlet](https://industrialcyber.co/) | Centralised info about vendor news and other articles on ICS and OT |
| [ICS and OT related conferences](https://sectube.tv/categories/ics-and-ot) |ICS and OT related conferences|

## ICS news article

| Title | Description |
| ----- | ----------- |
| [OPC UA Deep Dive: A Complete Guide to the OPC UA Attack Surface - Claroty](https://claroty.com/team82/research/opc-ua-deep-dive-a-complete-guide-to-the-opc-ua-attack-surface) | A 10-step article on the OPC UA Attack SUrface |
| [Evil PLC Attack: Weaponizing PLCs - Claroty](https://claroty.com/team82/research/white-papers/evil-plc-attack-weaponizing-plcs) | Team82 white paper on Evil PLC Attack |
| [Siemens simatic exploit article](https://securityaffairs.com/93939/ics-scada/siemens-simatic-flaw.html) | Experts found undocumented access feature in Siemens SIMATIC PLCs  |
| [Sandworm Disrupts Power in Ukraine Using a Novel Attack Against Operational Technology](https://www.mandiant.com/resources/blog/sandworm-disrupts-power-ukraine-operational-technology) | A 09-2023 article by Mandiant about the Sandworm disrupt power in Ukraine. Threat Intelligence is great, Mandiant does it better. |
| [Russian RE Modicon PLC](https://habr.com/ru/articles/752178/) | Some Russian who reverse-engineered the Modicon PLC from Schneider  |
| [Assessing the BACnet Control System Vulnerability - Dragos](https://www.dragos.com/blog/industry-news/assessing-the-bacnet-control-system-vulnerability/) | A 3mn-read article by Dragos on how to assess the BACnet Control System Vulnerability |
| [Article about offensive onsint on OT equipement](https://www.offensiveosint.io/offensive-osint-s01e03-intelligence-gathering-on-critical-infrastructure-in-southeast-asia/) | Offensive OSINT s01e04 - Intelligence gathering on critical infrastructure in Southeast Asia |
| [Nozomi Hour  november 2023](https://www.nozominetworks.com/resources/nozomi-hour-the-latest-ot-iot-security-insights?utm_content=278710155&utm_medium=social&utm_source=linkedin&hss_channel=lcp-5093151) | Nozomi Hour is usually a 40mn video of the Threat Landscape, posted each semester. Feel free to update yourselves with these links, it's a great source of info for your cyberwatch. |
| [OT Hunt: Finding ICS/OT with ZoomEye](https://alhasawi.medium.com/ot-hunt-finding-ics-ot-with-zoomeye-2fdb303b7f01) | Article on ZoomEye and how to use it. It's not that incredible article but it can help |
| [Water management system hack](https://arstechnica.com/security/2023/11/2-municipal-water-facilities-report-falling-to-hackers-in-separate-breaches/) | 2 municipal water facilities report falling to hackers in separate breaches |
| [widely used modems in industrial iot devices open to sms attack](https://www.bleepingcomputer.com/news/security/widely-used-modems-in-industrial-iot-devices-open-to-sms-attack/) | widely used modems in industrial iot devices open to sms attack|
| [KNX protocol base locker attack summary](https://limessecurity.com/en/knxlock/) | KNXlock – an attack campaign against KNX-based building automation systems |


## ICS books

| Title | Description |
| ----- | ----------- |
| [ISC security monitoring from Packt (second edition)](http://cdn.ttgtmedia.com/rms/editorial/bookshelf-industrialcybersecurity-excerpt.pdf) | ICS security from Packt written by Pascal Ackerman, second edition   |  
| [ICS field book](https://www.techdata.com/techsolutions/security/files/Navigating_Industrial_Cybersecurity_A_Field_Guide.pdf) | Basic but useful stuff on Industrial Security |
| [Industrial Network Security : Securing critical infrastructure network](https://drive.google.com/file/d/1LHpUdxqGotrotCHPg-6fzJfHHJC6jG25/view) | The best book you can find yet (from personal experience) |        
| [SCADA for Relay Technicians](https://na.eventscloud.com/file_uploads/ea71f859feae020526fd797b0195b9eb_SCADAforRelayTechs-SlidesNotes-HRS2019.pdf) | 2019 book for SCADA beginners |
| [Cybersécurité des systèmes industriels par Jean-Marie Flaus ](https://www.amazon.fr/Cybers%C3%A9curit%C3%A9-syst%C3%A8mes-industriels-Jean-Marie-Flaus/dp/1784055344) | French book on the ICS system |
| [The Industrial Control System Cyber Kill Chain](https://icscsi.org/library/Documents/White_Papers/SANS%20-%20ICS%20Cyber%20Kill%20Chain.pdf) | The Industrial Control System Cyber Kill Chain writen in October 2015 by SANS|
| [The ICS Cybersecurity Field Manual: VOL. 1-3 ](https://www.amazon.fr/ICS-Cybersecurity-Field-Manual-EXCLUSIVE/dp/B0CGG6GMHW) |The ICS Cybersecurity Field Manual: VOL. 1-3 Plus EXCLUSIVE BONUS material |


# ICS_Forum

| Title | Description |
| ----- | ----------- |
| [International PLC Forum](https://plcforum.uz.ua/)  | International PLC Forum |

---
# Hardware

## Hardware Materials and Emulator

| Title | Description |
| ----- | ----------- |
| [Online Circuit Emulator](https://falstad.com/circuit/circuitjs.html) | A visualization of how electronic circuits are working | 
| [IC Logos  Elnec](https://www.elnec.com/en/support/ic-logos/?method=logo) | Programmable IC Logos |
| [An Affordable And Programmable PLC Hackaday](https://hackaday.com/2022/12/08/an-affordable-and-programmable-plc/) | A review of an Affordable and Programmable PLC |
| [TechInfoDepot Wiki](https://techinfodepot.shoutwiki.com/wiki/Main_Page) | Wikipedia for Hardware, but it's not wikipedia |

## Hardware Hacking tutorials

| Title | Description |
| ----- | ----------- |
| [#01 - Identifying Components - Hardware Hacking Tutorial](https://www.youtube.com/watch?v=LSQf3iuluYo&list=PLoFdAHrZtKkhcd9k8ZcR4th8Q8PNOx7iU&ab_channel=MakeMeHack) | A 15mn-tutorial video on youtube if you're looking for a very good introduction to hardware hacking | 
| [Make Me Hack - A hardware reverse youtube channel](https://www.youtube.com/@MakeMeHack) | Everything related to Hardware Hacking and Reverse Engineering including tutorials for beginners and more advanced stuff |

## Datasheet Database

| Title | Description |
| ----- | ----------- |
| [Datasheet Database: alldatasheet](https://www.alldatasheet.com/) | Everything's in the title | 
| [Datasheet Database: datasheetcatalog](https://www.datasheetcatalog.com/) | DatasheetCatalog.com is free an online datasheet source for electronic components and semiconductors from multiple constructors |
| [Datasheet Database: datasheets](https://www.datasheets.com/) | Datasheets on electronic components |

## Integrated compoment info browser

| Title | Description |
| ----- | ----------- |
| [Online Circuit emulator](https://falstad.com/circuit/circuitjs.html) | Electronic circuit Emulator | 
| [IC logo Database](https://www.elnec.com/en/support/ic-logos/?method=logo) | Everything's in the title |
| [An Affordable And Programmable PLC Hackaday](https://hackaday.com/2022/12/08/an-affordable-and-programmable-plc/) | A review of an alternative of a PLC |
| [TechInfoDepot Wiki](https://techinfodepot.shoutwiki.com/wiki/Main_Page) | Wiki about ICS, but it's not wikipedia |

---
# ICS Training

| Title | Description |
| ----- | ----------- |
| [ICS Training Calendar  CISA](https://www.cisa.gov/ics-training-calendar) | Basically the training calendar of the CISA |
| [ICS 301v Review · Aaron Hoffmann](https://aaron-hoffmann.com/posts/ics-301v-review/) | A free online course on ICS 301v made by Aaron Hoffmann |    
| [HOME  Dean Parsons](https://www.icsdefenseforce.com/) | The home page of Dean Parsons, a major ICS expert, instructor & defender |
| [Assessing and exploiting control systems IIOT](https://downturk.net/2825155-scada-pentesting-brucon.html) | Free e-learning tutorial on SCADA security |
| [Global Industrial Cyber Security Professional (GICSP)](https://www.credly.com/badges/252931d5-7467-40df-bba9-e4aa857b0c50/linked_in?t=s69v1d) | GICSP home page for this certification |
| [ICS Cyber conference](https://www.icscybersecurityconference.com/) | Some conference for ICS |
| [ISA secure certifications program](https://isasecure.org/) | The ISASecure program delivers OT cybersecurity certifications. |
| [Industrial Control System Cyber Security Institute](https://icscsi.org/training.html) |Industrial Control System Cyber Security Institute training page|


---
# ICS Law Requirement-guide and Standart

| Title | Description |
| ----- | ----------- |
| [OPC UA Security Analysis ](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPCUA/OPCUA_2022_EN.pdf?__blob=publicationFile&v=4) | OPC UA Security Analysis from the German Governement |     
| [CWE VIEW: Weaknesses Addressed by ISA/IEC 62443 Requirements](https://cwe.mitre.org/data/definitions/1424.html) | This view (slice) covers weaknesses that are addressed by following requirements in the ISA/IEC 62443 series of standards for industrial automation and control systems (IACS). Members of the CWE ICS/OT SIG analyzed a set of CWEs and mapped them to specific requirements covered by ISA/IEC 62443. |
| [​​​​​​NERC Reliability Standards ](https://www.nerc.com/pa/Stand/Pages/Default.aspx) | NERC Reliability Standards are developed using an industry-driven, process that ensures the process is open to all persons who are directly and materially affected by the reliability of the North American bulk power system; |

## PCA PRA Risk management

| Title | Description |
| ----- | ----------- |
| [IRG on Water sector](https://www.ic3.gov/Media/News/2024/240118-2.pdf)| Incident Response Guide Water and Wastewater Sector |
| [IACS System Testing and Assessment Rating Score Calculator](https://iacs-star-calculator.com/iacs_star_calculator.html) | A method on how to assess and rate a vulnerability |
| [(Risk Management) EBIOS RM Method](https://cyber.gouv.fr/sites/default/files/2018/10/guide-methode-ebios-risk-manager.pdf) | The french way of assess the risk, with its 2018 version. You like it ? It's french. |

## ICS Requirement guide

| Title | Description |
| ----- | ----------- |
| [DOD requirement propositions](https://dl.dod.cyber.mil/wp-content/uploads/external/pdf/Jan_26_Control_Systems_SRG.pdf) | DEPARTMENT OF DEFENSE CONTROL SYSTEMS SECURITY REQUIREMENTS GUIDE |
| [NIST Special Publication SP 800-82r3 Guide to Operational Technology Security](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf) | Fundamental requirement for anybody who wants to start a OT security program |
| [Saudi Arabia Operatinos Technology Cyber Control](https://nca.gov.sa/otcc_en.pdf) | Saudi Arabia versions of implementations of different requirement|


## ICS Law and Act

| Title | Description |
| ----- | ----------- |
| [NIS directive in eatch EU country](https://digital-strategy.ec.europa.eu/en/policies/nis-directive-france) | specifications and informations about implementations of the NIS directiv in eatch EU country|
| [The NIST Cybersecurity Framework (CSF) 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) | The NIST Cybersecurity Framework (CSF) 2.0 provides guidance to industry, government agencies, and other organizations to manage cybersecurity risks. It offers a taxonomy of high- level cybersecurity outcomes that can be used by any organization — regardless of its size, sector, or maturity — to better understand, assess, prioritize, and communicate its cybersecurity efforts. |
| [ (UK)  Control Of Major Accident Hazards Regulations 2015 (COMAH)](https://www.hse.gov.uk/comah/background/comah15.htm) | Everything's in the title |
| [CISA on CIRCIA](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia) | In March 2022, President Biden signed into law the Cyber Incident Reporting for Critical Infrastructure Act of 2022 (CIRCIA). Enactment of CIRCIA marked an important milestone in improving America’s cybersecurity by, among other things, requiring the Cybersecurity and Infrastructure Security Agency (CISA) to develop and implement regulations requiring covered entities to report covered cyber incidents and ransomware payments to CISA. |

---
## ICS Group Alliance and Committee

| Title | Description |
| ----- | ----------- |
| [ISA Global Cyber Alliance](https://isagca.org/) | The main page of the ISA Global Cybersecurity Alliance (ISAGCA), a global consortium working to secure critical infrastructure |
| [Institute of Electrical and Electronics Engineers](https://www.ieee.org/) | not full ICS oriented , but one of the biggest organisations in the electrical and  electronics engeniering field|
| [The ICS Advisory Project](https://github.com/icsadvprj/ICS-Advisory-Project) | The ICS Advisory Project is an open-source project to provide DHS CISA ICS Advisories data in Comma Separated Value (CSV) format to support vulnerability analysis for the ICS/OT community.  |
| [ENISA website](https://www.enisa.europa.eu/) | European Union Agency for cybersecurity|

---
# ICS Vendor and equipement

## ICS security Equipement

| Title | Description |
| ----- | ----------- |
| [STORMSHIELD-SNi40-Datasheet ](https://www.stormshield-utm.eu/wp-content/uploads/2018/02/STORMSHIELD-SNi40-Datasheet.pdf?_sm_pdc=1&_sm_rid=P2N0B3JRtHtVPS50K3BjVdtssQbMLWB37kPS34r) | Stormshield monitoring & security solution for industries |
| [Checkpoint 1570R-rugged-security-gateway-datasheet ](https://www.checkpoint.com/downloads/products/1570R-rugged-security-gateway-datasheet.pdf) | The Check Point NGFW description sheet | 
| [Nozomie Saas tours ](https://www.nozominetworks.com/product-tours/asset-inventory) | Tour of the security platform of nozomie|

## ICS Security Vendor

| Title | Description |
| ----- | ----------- |
| [Nozomi Network Solutions](https://www.nozominetworks.com/solutions/threat-detection-and-response) | The home page of Nozomi's Threat Detection & Response for Critical Infrastructure & Industrial Security Teams |
| [SIGASEC](https://sigasec.com/) | A collection of monitoring solutions for OT network |
| [Leroy Automation](https://www.leroy-automation.com/gammes/range_tes/) | French PLC manufacturer|
| [waterfall security](https://waterfall-security.com/) ||
| [Owlcyberdefence](https://owlcyberdefense.com/) |data diode provider|
| [Custocy](https://www.custocy.ai/) | they do OT stuff |

# ICS Blue Team

## ICS Forensic

| Title | Description |
| ----- | ----------- |
| [Microsoft ICS Forensic Tools](https://github.com/microsoft/ics-forensics-tools) | Microsoft opensource ICS forensic tools |
| [Claroty team 82 forensic plogpost on unitronix PLC](https://fr.claroty.com/team82/research/from-exploits-to-forensics-unraveling-the-unitronics-attack) | From Exploits to Forensics: Unraveling the Unitronics Attack |

## ICS SOC

| Title | Description |
| ----- | ----------- |
| [Malcolm ICS](https://github.com/cisagov/Malcolm/blob/main/docs/live-analysis.md) | Malcolm is a powerful network traffic analysis maintained and updated by CISA and the Idaho National Laboratory (INL)|
| [Documentation for Malcolm ICS](https://malcolm.fyi/docs/) | Documentation for Malcolm ICS |

### ICS Rules

| Title | Description |
| ----- | ----------- |
| [Suricata rules for ICS detections](https://github.com/cisagov/Malcolm/tree/main/suricata/rules-default/OT/malcolm) | A collection of Suricata rules for ICS detections (Unitronics & Zyxel) |
| [Standard rules for custom protocols](https://github.com/OISF/suricata/tree/main/rules) | Standard rules for custom protocols like DNP3, ENIP, and Modbus |
| [Suricata rules for Nmap detections](https://github.com/CyberICS/Suricata-Rules-for-ICS-SCADA) | Suricata rules for detecting Nmap fingerprinting packets sent for ICS protocols |
| [Snort rules for exploit detections](https://github.com/nsacyber/ELITEWOLF) | NSA-backed repository for exploit detection in ICS environments |



# ICS Exploit Pentest & Red Team

| Title | Description |
| ----- | ----------- |
| [PLC Hacking (Pt. 1)  Redfox Security](https://redfoxsec.com/blog/plc-hacking-part-1/) | [Down for the moment] A tutorial on PLC hacking |   
| [Let’s Call It a Day — Virtual SCADA Hacking with GRFICSv2 Part 1  ](https://medium.com/@kelvin.w/lets-call-it-a-day-virtual-scada-hacking-with-grficsv2-part-1-4c0dd257724e) | A tutorial on how to exploit built-in ICS functionality to shut down a virtual plant simulator |
| [Going Out With a Bang — Virtual SCADA Hacking with GRFICSv2 Part 2 ](https://systemweakness.com/going-out-with-a-bang-virtual-scada-hacking-with-grficsv2-part-2-3db8a03c45ec) | Well, it's the 2nd part of the article below |
| [Fortiphyd Logic - YouTube](https://www.youtube.com/channel/UCt8y1lf8UBoZipoLj0a8pVA) | A gold mine of a youtube channel about built solutions for security and operations in IT and OT |  
| [ControlThings.io - Tools](https://www.controlthings.io/tools) | A collection of tools for OT/ICS pentesting made by ControlThings |
| [Bypassing Authentication in Schneider Electric PLCs (M340/M580)](https://medium.com/tenable-techblog/examining-crypto-and-bypassing-authentication-in-schneider-electric-plcs-m340-m580-f37cf9f3ff34) | Examining Crypto and Bypassing Authentication in Schneider Electric PLCs (M340/M580) |
| [Schneider eletric Exploit PoC](https://github.com/0xedh/schneider_plc_exploit/tree/main) | Modicon M580/M340 Safety Protection bypass and utils.|
| [FuzzySully](https://github.com/ANSSI-FR/fuzzysully) |FuzzySully is an OPC UA fuzzer built upon Fuzzowski. It is a specialized testing tool designed to identify vulnerabilities and bugs in OPC UA implementations. The fuzzer operates by generating and sending a large number of malformed or unexpected messages to an OPC UA server or client, with the goal of triggering unexpected behavior or crashes.|
| [Compromising Critical Infrastructure by Reversing SCADA Software](https://vrls.ws/posts/2025/04/red-team-compromising-critical-infrastructure-by-reversing-scada-software/) ||



---
# Many thanks to our contributors

[Biero](https://github.com/biero-el-corridor), [Winter-lab](https://github.com/Winter-lab/), [RedBlue232](https://github.com/RedBlue232), [HashBadG](https://github.com/HashBadG/), [summoningshells](https://github.com/summoningshells).