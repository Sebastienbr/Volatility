Filelist plugin
-------------------------
Filelist is used to list files that can be extracted by Volatility's dumpfiles plugin [1].

Here's some examples on how to use the filelist plugin. Memory sample [2] was used for the examples. 

**List exe files in the memory dump:**

	C:\Volatility>python vol.py -f Bob.vmem filelist -r \.exe
	Volatility Foundation Volatility Framework 2.3
	Offset       PID   Present Type                 File Name
	------------ ----- ------- -------------------- --------------------------------------------------------------------------------------
	0x81dd28d0     548 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\smss.exe
	0x822741c8     612 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\csrss.exe
	0x82264028     644 Yes     DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\sdra64.exe
	0x81d45b00     644 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\winlogon.exe
	0x81d45b00     644 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\winlogon.exe
	0x822ec7f8     688 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\services.exe
	0x81e5c028     700 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\lsass.exe
	0x8226ba70     852 Yes     ImageSectionObject   \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\vmacthlp.exe
	0x81d476d8     880 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\svchost.exe
	0x81d476d8     880 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\svchost.exe
	0x822dfbd0    1460 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\spoolsv.exe
	0x82113220    1628 Yes     ImageSectionObject   \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\vmtoolsd.exe
	0x81d163f8    1836 Yes     ImageSectionObject   \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMUpgradeHelper.exe
	0x81cf83a0    2024 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\alg.exe
	0x81e584c0    1756 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\explorer.exe
	0x81e584c0    1756 Yes     DataSectionObject    \Device\HarddiskVolume1\WINDOWS\explorer.exe
	0x81ca9028    1108 Yes     ImageSectionObject   \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMwareTray.exe
	0x81ca9028    1108 No      DataSectionObject    \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMwareTray.exe
	0x820cdbd8    1116 Yes     ImageSectionObject   \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMwareUser.exe
	0x820a83a8    1132 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\wscntfy.exe
	0x81cbdd18     244 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\msiexec.exe
	0x81cbdd18     244 Yes     DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\msiexec.exe
	0x820c3298     440 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\wuauclt.exe
	0x820c3298     440 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\wuauclt.exe
	0x81dc2e90     888 Yes     ImageSectionObject   \Device\HarddiskVolume1\Program Files\Mozilla Firefox\firefox.exe
	0x81dc2e90     888 Yes     DataSectionObject    \Device\HarddiskVolume1\Program Files\Mozilla Firefox\firefox.exe
	0x82077868    1752 Yes     ImageSectionObject   \Device\HarddiskVolume1\Program Files\Adobe\Acrobat 6.0\Reader\AcroRd32.exe
	0x82077868    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\Program Files\Adobe\Acrobat 6.0\Reader\AcroRd32.exe


**List all files opened by PID 644 (i.e: winlogon.exe with Zeus/Zbot injected):**

	C:\Volatility>python vol.py -f Bob.vmem filelist -p 644
	Volatility Foundation Volatility Framework 2.3
	Offset       PID   Present Type                 File Name
	------------ ----- ------- -------------------- -------------------------------------------------------------------------------------
	0x82264028     644 Yes     DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\sdra64.exe
	0x81ebe598     644 Yes     DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\lowsec\user.ds
	0x822e3ea0     644 Yes     DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\lowsec\local.ds
	0x81f14590     644 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\unicode.nls
	0x81ebe028     644 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\sortkey.nls
	0x81e4f4b0     644 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\locale.nls
	0x822a4210     644 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\sorttbls.nls
	0x822da598     644 No      DataSectionObject    \Device\HarddiskVolume1\WINDOWS\system32\ctype.nls
	0x81d45b00     644 Yes     ImageSectionObject   \Device\HarddiskVolume1\WINDOWS\system32\winlogon.exe
	[…]


**List DataSectionObject files listed in the HandleTable for the AcroRd32.exe process (PID 1752):**

	C:\Volatility>python vol.py -f Bob.vmem filelist -p 1752 -F DataSectionObject,HandleTable
	Volatility Foundation Volatility Framework 2.3
	Offset       PID   Present Type                 File Name
	------------ ----- ------- -------------------- -----------------------------------------------------------------------------------------------
	0x81c8c8e8    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\Acr107.tmp
	0x8206f028    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\Acr106.tmp
	0x81dfadf0    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\plugtmp\PDF.php
	0x81ec1960    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\Program Files\Adobe\Acrobat 6.0\Reader\Messages\ENU\RdrMsgENU.pdf
	0x81ec8f90    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\Documents and Settings...Temporary Internet Files\Content.IE5\index.dat
	0x820da3d8    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\Documents and Settings\Administrator\Cookies\index.dat
	0x820da470    1752 Yes     DataSectionObject    \Device\HarddiskVolume1\Documents and Settings...r\Local Settings\History\History.IE5\index.dat







VirusTotal plugin
-------------------------
Virustotal plugin is used to query/submit cached memory files to VirusTotal.

Here's some examples on how to use the virustotal plugin. Memory sample [2] was used for the examples.  

Please note that Virustotal plugin does not submit any files to VT by default. To use this plugin, edit virustotal.py and enter your VT API Key. By default, the plugin operate in public mode (i.e: maximum 4 requests per minute to VT). However, if you have a private key, it's possible to ajust the delay between queries with the --delay option.


**Query Virustotal for the file sdra64.exe present in memory:**

	C:\Volatility>python vol.py -f Bob.vmem virustotal -r sdra64\.exe
	Volatility Foundation Volatility Framework 2.3
	************************************************************************
	File: \Device\HarddiskVolume1\WINDOWS\system32\sdra64.exe
	Cache file type: DataSectionObject
	PID: 644
	MD5: b3e40cb29a3125ac862570ed5b5212a5
	Detection ratio: 38/41
	Analysis date: 2010-05-23 00:22:26
	
	Antivirus                 Result                                   Update
	------------------------- ---------------------------------------- ------------
	nProtect                  Trojan.Generic.KD.387                    20100522
	CAT-QuickHeal             Win32.Packed.Krap.ao.4                   20100521
	McAfee                    PWS-Zbot.gen.ak                          20100523
	TheHacker                 Trojan/Kryptik.cqz                       20100522
	VirusBuster               Trojan.Kryptik.IBE                       20100522
	NOD32                     a variant of Win32/Kryptik.CQZ           20100522
	F-Prot                    W32/Agent.FG.gen!Eldorado                20100523
	Symantec                  Packed.Generic.292                       20100522
	Norman                    W32/Zbot.PFX                             20100522
	TrendMicro-HouseCall      TROJ_ZBOT.AZR                            20100523
	Avast                     Win32:Crypt-FWN                          20100522
	eSafe                     None                                     20100520
	ClamAV                    Trojan.Zbot-8228                         20100522
	Kaspersky                 Packed.Win32.Krap.ao                     20100522
	BitDefender               Trojan.Generic.KD.387                    20100523
	Comodo                    TrojWare.Win32.TrojanSpy.Zbot.Gen        20100522
	F-Secure                  Trojan.Generic.KD.387                    20100522
	DrWeb                     Trojan.Winlock.1115                      20100522
	AntiVir                   TR/Agent.AO.177                          20100521
	TrendMicro                TROJ_ZBOT.AZR                            20100522
	McAfee-GW-Edition         PWS-Zbot.gen.ak                          20100522
	Sophos                    Mal/FakeAV-BW                            20100522
	eTrust-Vet                Win32/FakeAV!generic                     20100521
	Authentium                W32/Agent.FG.gen!Eldorado                20100522
	Jiangmin                  Packed.Krap.cfls                         20100522
	Antiy-AVL                 Packed/Win32.Krap.gen                    20100521
	a-squared                 Packed.Win32.Krap!IK                     20100510
	Microsoft                 Trojan:Win32/Malagent                    20100522
	ViRobot                   None                                     20100522
	Prevx                     Medium Risk Malware                      20100523
	GData                     Trojan.Generic.KD.387                    20100522
	AhnLab-V3                 Win-Trojan/Burnix.Gen                    20100522
	VBA32                     Trojan.Win32.Inject.anij                 20100522
	Sunbelt                   Trojan-Spy.Win32.Zbot.gen (v)            20100522
	PCTools                   HeurEngine.MaliciousPacker               20100522
	Rising                    Trojan.Win32.Generic.51FFF748            20100522
	Ikarus                    Packed.Win32.Krap                        20100522
	Fortinet                  None                                     20100522
	AVG                       Cryptic.BL                               20100523
	Panda                     Trj/Krap.Y                               20100522
	Avast5                    Win32:Crypt-FWN                          20100522


**Query DataSectionObject files listed in the HandleTable for the AcroRd32.exe process (PID 1752):**

	C:\Volatility>python vol.py -f Bob.vmem virustotal -p 1752 -F DataSectionObject,HandleTable
	Volatility Foundation Volatility Framework 2.3
	************************************************************************
	File: \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\Acr107.tmp
	Cache file type: DataSectionObject
	PID: 1752
	MD5: aeb2581f6c99b4434fb8ed96aeb3e43d
	Detection ratio: 0/42
	Analysis date: 2010-04-04 15:04:31
	
	************************************************************************
	File: \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\Acr106.tmp
	Cache file type: DataSectionObject
	PID: 1752
	MD5: c6ea3ec108b4610831883617dc877f4b
	Detection ratio: 0/42
	Analysis date: 2010-04-04 15:04:05
	
	************************************************************************
	File: \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\plugtmp\PDF.php
	Cache file type: DataSectionObject
	PID: 1752
	MD5: cb5bfbeaa27248ca8218414c61da9a56
	Detection ratio: 13/41
	Analysis date: 2010-05-13 13:08:49
	
	Antivirus                 Result                                   Update
	------------------------- ---------------------------------------- ------------
	nProtect                  Exploit.PDF-Name.Gen                     20100513
	CAT-QuickHeal             None                                     20100513
	McAfee                    None                                     20100513
	TheHacker                 None                                     20100513
	VirusBuster               None                                     20100512
	NOD32                     None                                     20100513
	F-Prot                    None                                     20100513
	Symantec                  Bloodhound.PDF.8                         20100513
	Norman                    None                                     20100513
	TrendMicro-HouseCall      None                                     20100513
	Avast                     JS:Pdfka-gen                             20100513
	eSafe                     None                                     20100511
	ClamAV                    None                                     20100513
	Kaspersky                 None                                     20100513
	BitDefender               Exploit.PDF-Name.Gen                     20100513
	Comodo                    UnclassifiedMalware                      20100513
	F-Secure                  Exploit.PDF-Name.Gen                     20100513
	DrWeb                     None                                     20100513
	AntiVir                   None                                     20100512
	TrendMicro                None                                     20100513
	McAfee-GW-Edition         None                                     20100513
	Sophos                    Mal/PDFEx-D                              20100513
	eTrust-Vet                None                                     20100513
	Authentium                None                                     20100513
	Jiangmin                  None                                     20100513
	Antiy-AVL                 None                                     20100513
	a-squared                 Exploit.Win32.Pdfjsc!IK                  20100510
	Microsoft                 Exploit:Win32/Pdfjsc.EF                  20100513
	ViRobot                   None                                     20100513
	Prevx                     None                                     20100513
	GData                     Exploit.PDF-Name.Gen                     20100513
	AhnLab-V3                 None                                     20100513
	VBA32                     None                                     20100513
	Sunbelt                   None                                     20100513
	PCTools                   HeurEngine.PDF                           20100513
	Rising                    None                                     20100513
	Ikarus                    Exploit.Win32.Pdfjsc                     20100513
	Fortinet                  None                                     20100513
	AVG                       None                                     20100513
	Panda                     None                                     201005
	Avast5                    JS:Pdfka-gen                             20100513
	************************************************************************
	File: \Device\HarddiskVolume1\Program Files\Adobe\Acrobat 6.0\Reader\Messages\ENU\RdrMsgENU.pdf
	Cache file type: DataSectionObject
	PID: 1752
	MD5: cd3c38c9c0e910bf1fe722871039cf3d
	Detection ratio: 0/42
	Analysis date: 2010-04-04 18:36:07
	
	************************************************************************
	File: \Device\HarddiskVolume1\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\index.dat
	Cache file type: DataSectionObject
	PID: 1752
	MD5: 1b6e92d96236f8d2307412283c7666cb
	File not present on VirusTotal
	************************************************************************
	File: \Device\HarddiskVolume1\Documents and Settings\Administrator\Cookies\index.dat
	Cache file type: DataSectionObject
	PID: 1752
	MD5: 7b00dbeb59f8fc8e70f291731bd36811
	File not present on VirusTotal
	************************************************************************
	File: \Device\HarddiskVolume1\Documents and Settings\Administrator\Local Settings\History\History.IE5\index.dat
	Cache file type: DataSectionObject
	PID: 1752
	MD5: b995dc0123737ae13a70f71c88657daf
	File not present on VirusTotal



Query all pdf.php files in memory (ignore case) and upload any file that is unknown to VirusTotal:

	C:\Volatility>python vol.py -f Bob.vmem virustotal -r pdf.php -i --submit
	Volatility Foundation Volatility Framework 2.3
	***********************************************************************
	File: \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\plugtmp\PDF.php
	Cache file type: DataSectionObject
	PID: 1752
	MD5: cb5bfbeaa27248ca8218414c61da9a56
	Detection ratio: 13/41
	Analysis date: 2010-05-13 13:08:49
	
	Antivirus                 Result                                   Update
	------------------------- ---------------------------------------- ------------
	nProtect                  Exploit.PDF-Name.Gen                     20100513
	CAT-QuickHeal             None                                     20100513
	McAfee                    None                                     20100513
	TheHacker                 None                                     20100513
	VirusBuster               None                                     20100512
	NOD32                     None                                     20100513
	F-Prot                    None                                     20100513
	Symantec                  Bloodhound.PDF.8                         20100513
	Norman                    None                                     20100513
	TrendMicro-HouseCall      None                                     20100513
	Avast                     JS:Pdfka-gen                             20100513
	eSafe                     None                                     20100511
	ClamAV                    None                                     20100513
	Kaspersky                 None                                     20100513
	BitDefender               Exploit.PDF-Name.Gen                     20100513
	Comodo                    UnclassifiedMalware                      20100513
	F-Secure                  Exploit.PDF-Name.Gen                     20100513
	DrWeb                     None                                     20100513
	AntiVir                   None                                     20100512
	TrendMicro                None                                     20100513
	McAfee-GW-Edition         None                                     20100513
	Sophos                    Mal/PDFEx-D                              20100513
	eTrust-Vet                None                                     20100513
	Authentium                None                                     20100513
	Jiangmin                  None                                     20100513
	Antiy-AVL                 None                                     20100513
	a-squared                 Exploit.Win32.Pdfjsc!IK                  20100510
	Microsoft                 Exploit:Win32/Pdfjsc.EF                  20100513
	ViRobot                   None                                     20100513
	Prevx                     None                                     20100513
	GData                     Exploit.PDF-Name.Gen                     20100513
	AhnLab-V3                 None                                     20100513
	VBA32                     None                                     20100513
	Sunbelt                   None                                     20100513
	PCTools                   HeurEngine.PDF                           20100513
	Rising                    None                                     20100513
	Ikarus                    Exploit.Win32.Pdfjsc                     20100513
	Fortinet                  None                                     20100513
	AVG                       None                                     20100513
	Panda                     None                                     20100512
	Avast5                    JS:Pdfka-gen                             20100513
	************************************************************************
	File: \Device\HarddiskVolume1\DOCUME~1\ADMINI~1\LOCALS~1\Temp\plugtmp\PDF.php
	Cache file type: SharedCacheMap
	PID: 1752
	MD5: ef6f0c1e573d6fbfa9c5b0d77cfbe2cd
	File not present on VirusTotal. Uploading file...
	Scan request successfully queued, come back later for the report
	
	Requested item is still queued for analysis...waiting 60 seconds
	Requested item is still queued for analysis...waiting 60 seconds
	Detection ratio: 17/40
	Analysis date: 2013-10-14 19:35:44
	
	Antivirus                 Result                                   Update
	------------------------- ---------------------------------------- ------------
	MicroWorld-eScan          Exploit.PDF-Name.Gen                     20131014
	nProtect                  Exploit.PDF-Name.Gen                     20131014
	CAT-QuickHeal             None                                     20131014
	McAfee                    None                                     20131014
	Malwarebytes              None                                     20131014
	K7AntiVirus               None                                     20131014
	K7GW                      None                                     20131014
	TheHacker                 None                                     20131014
	NANO-Antivirus            Exploit.Script.Pdfka.lcgj                20131014
	F-Prot                    None                                     20131014
	Symantec                  Bloodhound.PDF.8                         20131014
	Norman                    Obfuscated.JS                            20131014
	ByteHero                  None                                     20130923
	Avast                     JS:Pdfka-gen [Expl]                      20131014
	ClamAV                    Heuristics.PDF.ObfuscatedNameObject      20131013
	Kaspersky                 None                                     20131014
	BitDefender               Exploit.PDF-Name.Gen                     20131012
	Agnitum                   None                                     20131014
	ViRobot                   None                                     20131014
	Emsisoft                  Exploit.PDF-Name.Gen (B)                 20131014
	Comodo                    None                                     20131014
	DrWeb                     SCRIPT.Virus                             20131014
	AntiVir                   EXP/Pidief.OR                            20131014
	McAfee-GW-Edition         None                                     20131014
	Sophos                    Mal/PdfEx-C                              20131014
	Jiangmin                  None                                     20131014
	Panda                     None                                     20131014
	Antiy-AVL                 None                                     20131014
	Kingsoft                  None                                     20130829
	Microsoft                 Exploit:Win32/Pdfjsc.EF                  20131014
	SUPERAntiSpyware          None                                     20131014
	GData                     Exploit.PDF-Name.Gen                     20131014
	Commtouch                 PDF/Obfusc.G!Camelot                     20131014
	TotalDefense              None                                     20131011
	VBA32                     None                                     20131014
	PCTools                   HeurEngine.PDF                           20131002
	ESET-NOD32                None                                     20131014
	Ikarus                    Exploit.JS.Pdfka                         20131014
	Fortinet                  None                                     20131014
	Baidu-International       None                                     20131014


[1]: https://code.google.com/p/volatility/source/browse/trunk/volatility/plugins/dumpfiles.py
[2]: https://www.honeynet.org/challenges/2010_3_banking_troubles
