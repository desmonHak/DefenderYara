
rule _#Adware_Win32_ArcadeWeb{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 77 69 6f 6e 74 72 61 79 6d 74 78 } //1 awiontraymtx
		$a_01_1 = {41 70 70 44 61 74 61 4c 6f 77 5c 41 57 47 41 4d 45 43 4f 4e 46 49 47 } //1 AppDataLow\AWGAMECONFIG
		$a_01_2 = {61 72 63 61 64 65 77 65 62 2e 63 6f 6d } //1 arcadeweb.com
		$a_01_3 = {41 72 63 61 64 65 57 65 62 20 45 78 74 65 6e 73 69 6f 6e } //1 ArcadeWeb Extension
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#Adware_Win32_ArcadeWeb_2{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 72 63 61 64 65 57 65 62 20 55 6e 69 6e 73 74 61 6c 6c 65 72 00 } //1
		$a_01_1 = {25 73 5c 61 72 63 61 64 65 77 65 62 33 32 2e 64 6c 6c 00 } //1
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 41 72 63 61 64 65 57 65 62 00 } //1 潓瑦慷敲䅜灰慄慴潌屷牁慣敤敗b
		$a_01_3 = {61 72 63 61 64 65 77 65 62 2e 63 6f 6d 2f 61 6a 2f 64 65 61 63 74 69 76 61 74 65 2e 70 68 70 } //1 arcadeweb.com/aj/deactivate.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#Adware_Win32_ArcadeWeb_3{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 77 75 6e 2e 65 78 65 } //1 awun.exe
		$a_01_1 = {50 6c 65 61 73 65 20 72 65 62 6f 6f 74 20 79 6f 75 72 20 73 79 73 74 65 6d 20 6d 61 6e 75 61 6c 79 21 } //1 Please reboot your system manualy!
		$a_01_2 = {41 72 63 61 64 65 57 65 62 20 55 6e 69 6e 73 74 61 6c 6c 65 72 20 46 69 6e 69 73 68 } //1 ArcadeWeb Uninstaller Finish
		$a_01_3 = {61 72 63 61 64 65 77 65 62 33 32 2e 64 6c 6c } //1 arcadeweb32.dll
		$a_01_4 = {61 6a 2f 64 65 61 63 74 69 76 61 74 65 2e 70 68 } //1 aj/deactivate.ph
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule _#Adware_Win32_ArcadeWeb_4{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 57 20 52 65 67 69 73 74 72 79 20 72 65 6d 6f 76 61 6c } //1 AW Registry removal
		$a_03_1 = {61 72 63 61 64 65 77 65 62 66 69 72 65 66 6f 78 [0-01] 2e 64 6c 6c } //1
		$a_01_2 = {25 73 5c 61 72 63 61 64 65 77 65 62 33 32 2e 64 6c 6c } //1 %s\arcadeweb32.dll
		$a_01_3 = {61 77 5f 69 6e 73 74 61 6c 6c 5f 75 6e 69 6e 73 74 61 6c 6c 5f 73 61 66 65 67 75 61 72 64 } //1 aw_install_uninstall_safeguard
		$a_01_4 = {41 57 47 41 4d 45 43 4f 4e 46 49 47 } //1 AWGAMECONFIG
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#Adware_Win32_ArcadeWeb_5{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 57 65 78 74 65 6e 73 69 6f 6e 2e 6a 73 2e 74 6d 70 } //1 AWextension.js.tmp
		$a_01_1 = {61 77 75 6e 2e 65 78 65 } //1 awun.exe
		$a_01_2 = {45 6c 65 6d 65 6e 74 20 6d 75 7a 74 20 62 65 20 63 6c 6f 73 65 64 2e } //1 Element muzt be closed.
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 41 57 47 41 4d 45 43 4f 4e 46 49 47 } //1 Software\AppDataLow\AWGAMECONFIG
		$a_01_4 = {41 72 63 61 64 65 57 65 62 20 53 6f 66 74 77 61 72 65 20 49 6e 73 74 61 6c 6c 65 72 } //1 ArcadeWeb Software Installer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule _#Adware_Win32_ArcadeWeb_6{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 72 63 61 64 65 77 65 62 20 47 61 6d 69 6e 67 20 41 64 64 2d 6f 6e } //1 Arcadeweb Gaming Add-on
		$a_01_1 = {41 57 47 61 6d 65 73 2e 41 64 64 6f 6e } //1 AWGames.Addon
		$a_01_2 = {7b 32 41 30 34 41 31 44 30 2d 31 39 36 39 2d 34 30 30 65 2d 41 35 33 43 2d 36 41 35 34 33 33 41 34 42 36 35 38 7d } //1 {2A04A1D0-1969-400e-A53C-6A5433A4B658}
		$a_01_3 = {64 6f 6d 61 69 6e 3d 2e 61 72 63 61 64 65 77 65 62 2e 63 6f 6d 3b } //1 domain=.arcadeweb.com;
		$a_01_4 = {61 77 2f 67 65 74 45 78 74 65 72 6e 61 6c 47 61 6d 65 73 49 6e 66 6f 2f 74 69 63 6b 65 74 3d } //1 aw/getExternalGamesInfo/ticket=
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 41 57 47 41 4d 45 43 4f 4e 46 49 47 } //1 Software\AppDataLow\AWGAMECONFIG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule _#Adware_Win32_ArcadeWeb_7{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 72 63 61 64 65 57 65 62 20 53 6f 66 74 77 61 72 65 20 49 6e 73 74 61 6c 6c 65 72 00 } //1
		$a_01_1 = {61 72 63 61 64 65 77 65 62 63 68 72 6f 6d 65 2e 64 6c 6c 00 } //1
		$a_01_2 = {41 72 63 61 64 65 57 65 62 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 69 73 20 63 6f 6d 70 6c 65 74 65 64 2e 00 } //1
		$a_01_3 = {49 6e 73 74 61 6c 6c 69 6e 67 20 41 72 63 61 64 65 57 65 62 20 43 6c 69 65 6e 74 2e 2e 2e 00 } //1
		$a_01_4 = {74 65 78 74 6c 69 6e 6b 73 40 61 72 63 61 64 65 77 65 62 2e 63 6f 6d 00 } //1
		$a_01_5 = {61 72 63 61 64 65 77 65 62 2e 63 6f 6d 2f 61 6a 2f 69 6e 73 74 2e 70 68 70 } //1 arcadeweb.com/aj/inst.php
		$a_01_6 = {41 57 20 54 72 61 79 49 63 6f 6e 00 } //1 坁吠慲䥹潣n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule _#Adware_Win32_ArcadeWeb_8{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {c6 45 ec 69 c6 45 ed 65 c6 45 ee 78 c6 45 ef 70 c6 45 f0 6c c6 45 f1 6f c6 45 f2 72 c6 45 f3 65 c6 45 f4 2e c6 45 f5 65 c6 45 f6 78 c6 45 f7 65 88 5d f8 ff 15 } //1
		$a_03_1 = {5c 41 70 70 44 61 74 61 4c 6f 77 5c 41 57 47 ?? 4d 45 43 4f 4e 46 49 47 } //1
		$a_03_2 = {41 00 72 00 63 00 61 00 64 00 65 00 [0-04] 57 00 65 00 62 00 20 00 4c 00 4c 00 43 00 } //1
		$a_00_3 = {61 72 63 61 64 65 77 65 62 33 32 2e 64 6c 6c } //1 arcadeweb32.dll
		$a_00_4 = {49 6e 73 74 61 6c 6c 69 6e 67 20 41 72 63 61 64 65 57 65 62 20 43 6c 69 65 6e 74 2e 2e 2e 00 } //1
		$a_01_5 = {47 61 6d 65 20 41 64 64 2d 6f 6e 20 41 72 63 61 64 65 57 65 62 } //1 Game Add-on ArcadeWeb
		$a_01_6 = {65 77 65 62 00 00 00 00 61 72 63 61 64 00 00 00 68 74 74 70 3a 2f 2f 63 66 } //1
		$a_01_7 = {62 63 66 67 2e 42 61 63 6b 75 70 52 69 73 65 2e 63 6f 6d } //1 bcfg.BackupRise.com
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}
rule _#Adware_Win32_ArcadeWeb_9{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0b 00 00 "
		
	strings :
		$a_01_0 = {41 57 5f 54 52 41 59 5f 49 43 4f 4e 5f 4d 54 58 00 } //1
		$a_01_1 = {41 57 20 54 72 61 79 49 63 6f 6e 00 } //1 坁吠慲䥹潣n
		$a_01_2 = {61 72 63 61 64 65 77 65 62 2e 63 6f 6d 2f 67 61 6d 65 73 2e 70 68 70 3f 72 65 6c 3d 74 72 61 79 } //1 arcadeweb.com/games.php?rel=tray
		$a_01_3 = {61 77 75 70 64 61 74 65 2e 65 78 65 00 } //1
		$a_01_4 = {70 6c 61 79 73 75 73 68 69 73 6c 69 64 65 74 69 74 6c 65 00 } //1 汰祡畳桳獩楬敤楴汴e
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 41 72 63 61 64 65 57 65 62 00 } //1 潓瑦慷敲䅜灰慄慴潌屷牁慣敤敗b
		$a_01_6 = {41 56 43 41 57 53 79 73 74 65 6d 54 72 61 79 40 40 } //1 AVCAWSystemTray@@
		$a_01_7 = {3d 20 73 20 27 41 72 63 61 64 65 57 65 62 20 43 6c 61 73 73 27 } //1 = s 'ArcadeWeb Class'
		$a_01_8 = {61 77 6d 74 72 61 79 6d 74 78 } //1 awmtraymtx
		$a_01_9 = {69 6e 73 65 72 74 5f 65 78 70 69 72 65 5f 74 69 6d 65 00 00 69 6e 73 65 72 74 5f 6a 73 } //1
		$a_01_10 = {32 35 36 73 3e 27 20 69 73 20 6e 6f 74 20 77 65 6c 2d 66 6f 72 6d 65 64 2e } //1 256s>' is not wel-formed.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=4
 
}
rule _#Adware_Win32_ArcadeWeb_10{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 53 54 65 78 74 2e 44 4c 4c 00 44 6c 6c } //1 卐敔瑸䐮䱌䐀汬
		$a_01_1 = {70 6c 61 79 73 75 73 68 69 73 6c 69 64 65 } //1 playsushislide
		$a_01_2 = {2f 70 73 63 6f 6e 66 2e 70 68 70 } //1 /psconf.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_ArcadeWeb_11{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 72 63 61 64 65 77 65 62 33 32 2e 64 6c 6c } //1 arcadeweb32.dll
		$a_01_1 = {61 72 63 61 64 65 77 65 62 73 6c 69 64 65 } //1 arcadewebslide
		$a_01_2 = {61 72 63 61 64 65 77 65 62 2e 63 6f 6d 2f 61 6a 2f 75 70 64 61 74 65 2e 70 68 70 } //1 arcadeweb.com/aj/update.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_ArcadeWeb_12{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 69 72 65 66 6f 78 50 6c 75 67 69 6e 2e 64 6c 6c } //1 FirefoxPlugin.dll
		$a_01_1 = {63 66 2e 61 72 63 61 64 65 77 65 62 2e 63 6f 6d } //1 cf.arcadeweb.com
		$a_01_2 = {41 70 70 44 61 74 61 4c 6f 77 5c 41 57 47 41 4d 45 43 4f 4e 46 49 47 } //1 AppDataLow\AWGAMECONFIG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#Adware_Win32_ArcadeWeb_13{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 72 63 61 64 65 57 65 62 20 49 6e 73 74 61 6c 6c 65 72 } //10 ArcadeWeb Installer
		$a_01_1 = {55 6e 69 6e 73 74 61 6c 6c 5c 41 72 63 61 64 65 77 65 62 } //1 Uninstall\Arcadeweb
		$a_01_2 = {61 72 63 61 64 65 77 65 62 66 69 72 65 66 6f 78 2e 64 6c 6c } //1 arcadewebfirefox.dll
		$a_01_3 = {61 72 63 61 64 65 77 65 62 63 68 72 6f 6d 65 2e 64 6c 6c } //1 arcadewebchrome.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
rule _#Adware_Win32_ArcadeWeb_14{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR,6f 00 6f 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6a 2f 64 65 61 63 74 69 76 61 74 65 2e 70 68 70 } //100 aj/deactivate.php
		$a_01_1 = {41 72 63 61 64 65 57 65 62 20 55 6e 69 6e 73 74 61 6c 6c 65 72 } //10 ArcadeWeb Uninstaller
		$a_01_2 = {50 6c 61 79 53 75 73 68 69 20 75 6e 69 6e 73 74 61 6c 6c 65 72 } //10 PlaySushi uninstaller
		$a_01_3 = {61 72 63 61 64 65 77 65 62 33 32 2e 64 6c 6c } //1 arcadeweb32.dll
		$a_01_4 = {50 6c 61 79 53 75 73 68 69 33 32 2e 44 4c 4c } //1 PlaySushi32.DLL
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=111
 
}
rule _#Adware_Win32_ArcadeWeb_15{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 61 6e 64 69 6e 67 70 61 67 65 73 2e 70 6c 61 79 73 75 73 68 69 2e 63 6f 6d } //1 landingpages.playsushi.com
		$a_01_1 = {74 65 78 74 6c 69 6e 6b 73 40 70 6c 61 79 73 75 73 68 69 2e 63 6f 6d } //1 textlinks@playsushi.com
		$a_01_2 = {50 53 54 65 78 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 卐敔瑸䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_3 = {70 73 69 64 3a 25 64 7c 75 69 64 3a 25 73 7c 6c 6f 63 3a 25 64 7c 73 74 6a 73 3a 25 64 } //1 psid:%d|uid:%s|loc:%d|stjs:%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule _#Adware_Win32_ArcadeWeb_16{
	meta:
		description = "!#Adware:Win32/ArcadeWeb,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 04 01 3c 2b 74 25 3c 2f 74 1a 3c 3d 74 0f 3c 7e 74 04 88 07 } //10
		$a_01_1 = {6c 69 76 69 6e 67 70 6c 61 79 2e 63 6f 6d } //1 livingplay.com
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 50 6c 75 67 69 6e 73 5c 6e 70 44 69 73 70 6c 61 79 45 6e 67 69 6e 65 } //1 MozillaPlugins\npDisplayEngine
		$a_01_3 = {41 72 63 61 64 65 57 65 62 20 45 78 74 65 6e 73 69 6f 6e } //1 ArcadeWeb Extension
		$a_01_4 = {61 72 63 61 64 65 77 65 62 63 68 72 6f 6d 65 2e 64 6c 6c } //1 arcadewebchrome.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}