
rule _#HSTR_PUA_Win32_Obfuse{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 BCryptGenRandom
		$a_81_1 = {52 6d 53 74 61 72 74 53 65 73 73 69 6f 6e } //1 RmStartSession
		$a_81_2 = {53 6c 65 65 70 } //1 Sleep
		$a_81_3 = {72 6f 62 6c 6f 78 73 6f 6c 61 72 61 73 63 72 69 70 74 } //1 robloxsolarascript
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule _#HSTR_PUA_Win32_Obfuse_2{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 70 70 44 61 74 61 } //1 AppData
		$a_81_1 = {68 74 74 70 3a 2f 2f 77 69 6e 2d 6f 74 74 2e 35 35 6b 61 6e 74 75 2e 63 6f 6d 2f } //1 http://win-ott.55kantu.com/
		$a_81_2 = {68 74 74 70 3a 2f 2f 6a 74 74 2d 77 69 6e 2e 35 35 6b 61 6e 74 75 2e 63 6f 6d 2f } //1 http://jtt-win.55kantu.com/
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=2
 
}
rule _#HSTR_PUA_Win32_Obfuse_3{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 61 75 74 6f 72 75 6e } //1 /autorun
		$a_81_1 = {74 70 3a 2f 2f 73 68 72 65 64 64 65 72 2e 39 31 74 6f 6f 6c 62 6f 78 2e 63 6f 6d } //1 tp://shredder.91toolbox.com
		$a_81_2 = {5c 52 65 67 69 73 74 72 79 5c 55 73 65 72 5c } //1 \Registry\User\
		$a_81_3 = {55 6c 74 72 61 53 68 72 65 64 64 65 72 } //1 UltraShredder
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule _#HSTR_PUA_Win32_Obfuse_4{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {66 74 70 3a 2f 2f 31 36 32 2e 32 35 30 2e 31 32 34 2e 38 32 2f 4f 75 74 70 75 74 2e 7a 69 70 } //1 ftp://162.250.124.82/Output.zip
		$a_81_1 = {50 61 73 73 77 6f 72 64 3d 42 3f 69 38 67 35 76 39 37 2e 4b 4a 4b 68 2a 38 32 35 26 } //1 Password=B?i8g5v97.KJKh*825&
		$a_81_2 = {49 64 65 61 6c 57 65 69 67 68 74 20 53 65 74 75 70 20 50 61 63 6b 61 67 65 } //1 IdealWeight Setup Package
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule _#HSTR_PUA_Win32_Obfuse_5{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 42 61 73 65 4e 61 6d 65 64 4f 62 6a 65 63 74 73 5c 52 65 73 74 72 69 63 74 65 64 5c } //1 \BaseNamedObjects\Restricted\
		$a_81_1 = {72 45 34 38 34 37 45 44 30 38 38 36 36 34 35 38 46 38 44 44 33 35 46 39 34 42 33 37 30 30 31 43 30 } //1 rE4847ED08866458F8DD35F94B37001C0
		$a_81_2 = {2f 72 65 73 74 61 72 74 } //1 /restart
		$a_81_3 = {2f 66 6f 72 63 65 } //1 /force
		$a_81_4 = {42 72 6f 77 73 65 72 5f 53 65 61 72 63 68 } //1 Browser_Search
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_PUA_Win32_Obfuse_6{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_81_1 = {52 65 70 6c 61 63 65 46 69 6c 65 } //1 ReplaceFile
		$a_81_2 = {53 6c 65 65 70 } //1 Sleep
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_5 = {4f 6e 65 53 74 61 72 74 2e 61 69 } //1 OneStart.ai
		$a_81_6 = {4f 6e 65 53 74 61 72 74 20 49 6e 73 74 61 6c 6c 65 72 } //1 OneStart Installer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_PUA_Win32_Obfuse_7{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 2e 63 68 61 74 73 6f 75 2e 63 63 2f } //1 http://down.chatsou.cc/
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {47 70 74 42 72 6f 77 73 65 72 41 70 70 62 61 72 41 75 74 6f 53 74 61 72 74 } //1 GptBrowserAppbarAutoStart
		$a_81_3 = {5c 47 50 54 20 43 68 72 6f 6d 65 2e 6c 6e 6b } //1 \GPT Chrome.lnk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule _#HSTR_PUA_Win32_Obfuse_8{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {70 75 72 63 68 61 73 65 5f 63 6c 69 63 6b 65 64 } //1 purchase_clicked
		$a_81_1 = {4f 75 74 70 75 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 69 42 6f 79 73 6f 66 74 44 61 74 61 52 65 63 6f 76 65 72 79 2e 70 64 62 } //1 Output\x64\Release\iBoysoftDataRecovery.pdb
		$a_81_2 = {46 6f 72 63 65 52 65 6d 6f 76 65 } //1 ForceRemove
		$a_81_3 = {4d 33 20 44 61 74 61 20 52 65 63 6f 76 65 72 79 } //1 M3 Data Recovery
		$a_81_4 = {69 42 6f 79 73 6f 66 74 20 44 61 74 61 20 52 65 63 6f 76 65 72 79 } //1 iBoysoft Data Recovery
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_PUA_Win32_Obfuse_9{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //1 \Registry\Machine\System\CurrentControlSet\Services\
		$a_81_1 = {5c 44 65 76 69 63 65 5c 54 72 75 65 53 69 67 68 74 } //1 \Device\TrueSight
		$a_81_2 = {41 6e 74 69 72 6f 6f 74 6b 69 74 20 6d 6f 64 75 6c 65 } //1 Antirootkit module
		$a_81_3 = {41 64 6c 69 63 65 20 53 6f 66 74 77 61 72 65 } //1 Adlice Software
		$a_81_4 = {54 72 75 65 73 69 67 68 74 } //1 Truesight
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_PUA_Win32_Obfuse_10{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {52 65 73 74 61 72 74 42 79 52 65 73 74 61 72 74 4d 61 6e 61 67 65 72 } //1 RestartByRestartManager
		$a_81_1 = {61 4d 46 43 4c 69 6e 6b 5f 55 72 6c } //1 aMFCLink_Url
		$a_81_2 = {42 61 72 4e 61 6d 65 } //1 BarName
		$a_81_3 = {63 6d 64 69 63 6c 69 65 6e 74 } //1 cmdiclient
		$a_81_4 = {68 6b 65 79 5f 63 75 72 72 65 6e 74 5f 75 73 65 72 5c 73 6f 66 74 77 61 72 65 5c } //1 hkey_current_user\software\
		$a_81_5 = {48 57 65 6c 63 6f 6d 65 50 61 67 65 } //1 HWelcomePage
		$a_81_6 = {6b 41 70 61 72 74 6d 65 6e 74 } //1 kApartment
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_PUA_Win32_Obfuse_11{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_1 = {56 69 72 74 75 61 6c 46 72 65 65 } //1 VirtualFree
		$a_81_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 75 70 64 61 74 65 2d 70 69 63 2e 32 33 34 35 2e 63 63 2f 70 69 63 2f 70 69 63 6e 65 77 73 2f 69 6e 64 65 78 2e 70 68 70 } //1 https://update-pic.2345.cc/pic/picnews/index.php
		$a_81_4 = {70 69 63 5f 61 64 5f 72 61 6e 64 6f 6d 2e 64 61 74 } //1 pic_ad_random.dat
		$a_81_5 = {52 4f 4f 54 5c 43 49 4d 56 32 } //1 ROOT\CIMV2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_PUA_Win32_Obfuse_12{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 65 65 70 20 53 6f 66 74 77 61 72 65 20 49 6e 63 2e } //1 Deep Software Inc.
		$a_81_1 = {53 6f 66 74 41 63 74 69 76 69 74 79 20 4d 6f 6e 69 74 6f 72 20 63 6c 69 65 6e 74 20 61 70 70 } //1 SoftActivity Monitor client app
		$a_81_2 = {53 74 6f 70 20 26 52 65 63 6f 72 64 69 6e 67 } //1 Stop &Recording
		$a_81_3 = {73 74 6f 70 20 72 65 63 6f 72 64 69 6e 67 20 75 73 65 72 20 61 63 74 69 76 69 74 79 20 61 6e 64 20 74 72 61 63 6b 69 6e 67 20 79 6f 75 72 20 77 6f 72 6b 20 74 69 6d 65 3f } //1 stop recording user activity and tracking your work time?
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule _#HSTR_PUA_Win32_Obfuse_13{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 74 4d 69 6e 69 6d 69 7a 65 64 } //1 StartMinimized
		$a_81_1 = {72 65 73 74 61 72 74 61 70 70 63 6d 64 } //1 restartappcmd
		$a_81_2 = {73 74 61 72 74 61 70 70 66 69 72 73 74 } //1 startappfirst
		$a_81_3 = {73 69 6c 65 6e 74 61 6c 6c } //1 silentall
		$a_81_4 = {41 50 50 44 49 52 } //1 APPDIR
		$a_81_5 = {41 75 74 6f 55 70 64 61 74 65 50 6f 6c 69 63 79 } //1 AutoUpdatePolicy
		$a_81_6 = {63 61 70 68 79 6f 6e 2d 61 64 76 69 6e 73 74 2d 75 70 64 61 74 65 72 } //1 caphyon-advinst-updater
		$a_81_7 = {52 65 70 6c 61 63 65 73 } //1 Replaces
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#HSTR_PUA_Win32_Obfuse_14{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {42 46 69 73 68 50 6f 77 } //1 BFishPow
		$a_81_1 = {67 50 6c 75 67 69 6e 5c 44 61 74 61 43 65 6e 74 65 72 53 74 75 62 2e 64 6c 6c } //1 gPlugin\DataCenterStub.dll
		$a_81_2 = {68 74 74 70 3a 2f 2f 73 2e 63 69 74 79 68 75 69 74 65 63 68 2e 63 6f 6d 2f 62 66 69 73 68 73 65 61 72 63 68 } //1 http://s.cityhuitech.com/bfishsearch
		$a_81_3 = {42 69 67 46 69 73 68 42 75 69 64 65 72 2e 64 6c 6c } //1 BigFishBuider.dll
		$a_81_4 = {53 4f 46 54 57 41 52 45 5c 42 69 67 46 69 73 68 53 65 61 72 63 68 } //1 SOFTWARE\BigFishSearch
		$a_81_5 = {42 69 67 46 69 73 68 53 65 61 72 63 68 44 61 74 61 } //1 BigFishSearchData
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_PUA_Win32_Obfuse_15{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 61 70 69 2e 51 6f 73 } //1 Winapi.Qos
		$a_81_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_2 = {53 6c 65 65 70 } //1 Sleep
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_4 = {6a 6f 68 61 62 } //1 johab
		$a_81_5 = {4a 4c 5a 4d 41 44 65 63 6f 6d 70 53 6d 61 6c 6c } //1 JLZMADecompSmall
		$a_81_6 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 2e } //1 This installation was built with Inno Setup.
		$a_81_7 = {49 4d 44 6f 77 6e 6c 6f 61 64 65 72 20 } //1 IMDownloader 
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#HSTR_PUA_Win32_Obfuse_16{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {54 4d 6f 6e 69 74 6f 72 2e 54 53 70 69 6e 4c 6f 63 6b } //1 TMonitor.TSpinLock
		$a_81_1 = {54 4d 42 43 53 45 6e 63 6f 64 69 6e 67 } //1 TMBCSEncoding
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_3 = {44 65 73 74 72 6f 79 } //1 Destroy
		$a_81_4 = {7b 73 64 7d 5c 47 61 6d 65 73 5c 47 61 6d 65 20 4e 61 6d 65 } //1 {sd}\Games\Game Name
		$a_81_5 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 2e } //1 This installation was built with Inno Setup.
		$a_81_6 = {53 4b 44 20 49 6e 73 74 61 6c 6c 65 72 20 53 65 74 75 70 } //1 SKD Installer Setup
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_PUA_Win32_Obfuse_17{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 74 49 6e 64 65 78 } //1 StartIndex
		$a_81_1 = {53 6c 65 65 70 } //1 Sleep
		$a_81_2 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 } //1 GetCommandLine
		$a_81_3 = {6e 30 30 30 31 30 32 30 33 30 34 30 35 30 36 30 37 30 38 30 39 31 30 31 31 31 32 31 33 31 34 31 35 31 36 31 37 31 38 31 39 32 30 32 31 } //1 n00010203040506070809101112131415161718192021
		$a_81_4 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 2e } //1 This installation was built with Inno Setup.
		$a_81_5 = {4f 72 69 67 61 6d 69 20 53 74 75 64 69 6f 73 } //1 Origami Studios
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_PUA_Win32_Obfuse_18{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 61 63 69 64 69 63 6f 61 6c 61 2f } //1 https://raw.githubusercontent.com/acidicoala/
		$a_81_1 = {5c 53 6d 6f 6b 65 41 50 49 5c 53 6d 6f 6b 65 41 50 49 5c 4b 6f 61 6c 61 42 6f 78 5c 73 72 63 5c 6b 6f 61 6c 61 62 6f 78 5c 64 6c 6c 5f 6d 6f 6e 69 74 6f 72 2e 63 70 70 } //1 \SmokeAPI\SmokeAPI\KoalaBox\src\koalabox\dll_monitor.cpp
		$a_81_2 = {5c 53 6d 6f 6b 65 41 50 49 5c 53 6d 6f 6b 65 41 50 49 5c 4b 6f 61 6c 61 42 6f 78 5c 73 72 63 5c 6b 6f 61 6c 61 62 6f 78 5c 68 6f 6f 6b 2e 63 70 70 } //1 \SmokeAPI\SmokeAPI\KoalaBox\src\koalabox\hook.cpp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule _#HSTR_PUA_Win32_Obfuse_19{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {48 69 64 65 57 69 6e 64 6f 77 } //1 HideWindow
		$a_81_1 = {45 78 65 63 3a 20 63 6f 6d 6d 61 6e 64 3d } //1 Exec: command=
		$a_81_2 = {43 6f 70 79 46 69 6c 65 73 } //1 CopyFiles
		$a_81_3 = {44 65 6c 65 74 65 52 65 67 4b 65 79 3a } //1 DeleteRegKey:
		$a_81_4 = {57 72 69 74 65 52 65 67 42 69 6e } //1 WriteRegBin
		$a_81_5 = {69 6e 73 74 61 6c 6c 2e 6c 6f 67 } //1 install.log
		$a_81_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 Software\Microsoft\Windows\CurrentVersion
		$a_81_7 = {43 3a 5c 54 45 4d 50 5c 46 59 43 41 44 45 64 69 74 6f 72 } //1 C:\TEMP\FYCADEditor
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#HSTR_PUA_Win32_Obfuse_20{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 77 69 6e 2e 64 6f 77 6e 2e 35 35 6b 61 6e 74 75 2e 63 6f 6d 2f } //1 http://win.down.55kantu.com/
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {68 74 74 70 3a 2f 2f 72 65 63 68 61 72 67 65 2e 35 35 6b 61 6e 74 75 2e 63 6f 6d 2f } //1 http://recharge.55kantu.com/
		$a_81_3 = {68 74 74 70 3a 2f 2f 77 69 6e 2e 35 35 6b 61 6e 74 75 2e 63 6f 6d 2f } //1 http://win.55kantu.com/
		$a_81_4 = {68 74 74 70 3a 2f 2f 61 70 69 2e 35 35 6b 61 6e 74 75 2e 63 6f 6d 2f } //1 http://api.55kantu.com/
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=2
 
}
rule _#HSTR_PUA_Win32_Obfuse_21{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {69 6e 66 61 74 69 63 61 2d 73 65 72 76 69 63 65 2d 61 70 70 2e 65 78 65 } //1 infatica-service-app.exe
		$a_81_1 = {43 72 65 61 74 69 6e 67 20 72 65 67 69 73 74 72 79 20 65 6e 74 72 69 65 73 } //1 Creating registry entries
		$a_81_2 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_81_3 = {52 65 73 74 61 72 74 52 65 70 6c 61 63 65 } //1 RestartReplace
		$a_81_4 = {54 68 65 20 73 65 74 75 70 20 66 69 6c 65 73 20 61 72 65 20 63 6f 72 72 75 70 74 65 64 } //1 The setup files are corrupted
		$a_81_5 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 } //1 This installation was built with Inno Setup
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_PUA_Win32_Obfuse_22{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {31 39 66 66 33 65 39 63 33 36 30 32 61 65 38 65 38 34 31 39 32 35 62 62 34 36 31 61 30 61 64 62 30 36 34 61 31 66 31 39 30 33 36 36 37 61 35 65 30 64 38 37 65 38 66 36 30 38 66 34 32 35 61 63 } //1 19ff3e9c3602ae8e841925bb461a0adb064a1f1903667a5e0d87e8f608f425ac
		$a_81_1 = {43 72 79 70 74 69 63 2e 64 6c 6c } //1 Cryptic.dll
		$a_81_2 = {68 6f 73 74 66 78 72 5f 6d 61 69 6e 5f 62 75 6e 64 6c 65 5f 73 74 61 72 74 75 70 69 6e 66 6f } //1 hostfxr_main_bundle_startupinfo
		$a_81_3 = {5c 63 6f 72 65 68 6f 73 74 5c 61 70 70 68 6f 73 74 5c 73 74 61 6e 64 61 6c 6f 6e 65 5c 61 70 70 68 6f 73 74 2e 70 64 62 } //1 \corehost\apphost\standalone\apphost.pdb
		$a_81_4 = {68 6f 73 74 66 78 72 2e 64 6c 6c } //1 hostfxr.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_PUA_Win32_Obfuse_23{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {40 2e 74 76 6d 70 } //1 @.tvmp
		$a_81_1 = {2e 64 69 63 74 } //1 .dict
		$a_81_2 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //1 GetModuleHandleA
		$a_81_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_81_4 = {52 65 67 43 72 65 61 74 65 4b 65 79 45 78 41 } //1 RegCreateKeyExA
		$a_81_5 = {77 61 76 65 4f 75 74 55 6e 70 72 65 70 61 72 65 48 65 61 64 65 72 } //1 waveOutUnprepareHeader
		$a_81_6 = {47 65 74 53 79 73 74 65 6d 54 69 6d 65 41 73 46 69 6c 65 54 69 6d 65 } //1 GetSystemTimeAsFileTime
		$a_81_7 = {73 74 61 72 64 69 63 74 5f 4b 65 79 } //1 stardict_Key
		$a_81_8 = {73 74 61 72 64 69 63 74 5f 61 6c 69 79 75 6e } //1 stardict_aliyun
		$a_81_9 = {73 74 61 72 64 69 63 74 2d 65 64 69 74 6f 72 2e 64 6c 6c } //1 stardict-editor.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}
rule _#HSTR_PUA_Win32_Obfuse_24{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 61 70 68 79 6f 6e 2e 41 49 2e 45 78 74 55 49 2e 49 45 43 6c 69 63 6b 53 6f 75 6e 64 52 65 6d 6f 76 65 72 } //1 Caphyon.AI.ExtUI.IEClickSoundRemover
		$a_81_1 = {63 2f 63 6d 64 6c 6f 63 20 } //1 c/cmdloc 
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_81_3 = {43 72 65 61 74 65 53 68 6f 72 74 63 75 74 } //1 CreateShortcut
		$a_81_4 = {5c 73 65 74 75 70 5c 65 76 65 6e 74 73 79 73 74 65 6d 5c 49 6e 73 74 61 6c 6c 4d 6f 6e 69 74 6f 72 2e 63 70 70 } //1 \setup\eventsystem\InstallMonitor.cpp
		$a_81_5 = {4e 69 74 72 6f 20 50 44 46 20 50 72 6f 5c 6e 69 74 72 6f 5f 70 72 6f 31 34 5f 78 36 34 2e 6d 73 69 } //1 Nitro PDF Pro\nitro_pro14_x64.msi
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_PUA_Win32_Obfuse_25{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {68 6b 65 79 5f 6c 6f 63 61 6c 5f 6d 61 63 68 69 6e 65 5c 73 6f 66 74 77 61 72 65 5c } //1 hkey_local_machine\software\
		$a_81_1 = {52 65 73 74 61 72 74 42 79 52 65 73 74 61 72 74 4d 61 6e 61 67 65 72 } //1 RestartByRestartManager
		$a_81_2 = {43 70 70 53 65 74 75 70 2c 20 56 65 72 73 69 6f 6e } //1 CppSetup, Version
		$a_81_3 = {41 6e 6f 74 68 65 72 20 73 65 74 75 70 20 69 73 20 61 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 2c 20 70 6c 65 61 73 65 20 63 6c 6f 73 65 20 69 74 20 61 6e 64 20 74 72 79 20 61 67 61 69 6e } //1 Another setup is already running, please close it and try again
		$a_81_4 = {47 6c 6f 62 61 6c 5c 43 70 70 53 65 74 75 70 } //1 Global\CppSetup
		$a_81_5 = {5c 44 53 2d 50 6c 61 74 66 6f 72 6d 5c 43 70 70 49 6e 73 74 61 6c 6c 65 72 5c 43 70 70 53 65 74 75 70 5c 62 69 6e 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 43 70 70 53 65 74 75 70 2e 70 64 62 } //1 \DS-Platform\CppInstaller\CppSetup\bin\Win32\Release\CppSetup.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_PUA_Win32_Obfuse_26{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {6d 69 6e 69 5f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 mini_installer.exe
		$a_81_1 = {43 6f 6e 76 65 72 74 53 69 64 54 6f 53 74 72 69 6e 67 53 69 64 } //1 ConvertSidToStringSid
		$a_81_2 = {43 6f 6e 76 65 72 74 53 74 72 69 6e 67 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 54 6f 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 } //1 ConvertStringSecurityDescriptorToSecurityDescriptor
		$a_81_3 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_81_4 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //1 CryptImportKey
		$a_81_5 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f } //1 GetStartupInfo
		$a_81_6 = {53 6c 65 65 70 } //1 Sleep
		$a_81_7 = {4f 6e 65 53 74 61 72 74 20 49 6e 73 74 61 6c 6c 65 72 } //1 OneStart Installer
		$a_81_8 = {4f 6e 65 53 74 61 72 74 2e 61 69 } //1 OneStart.ai
		$a_81_9 = {31 37 65 31 33 31 37 66 36 39 36 30 65 33 61 30 62 66 39 64 63 63 33 37 31 36 31 33 63 39 38 61 36 64 37 64 62 37 30 31 } //1 17e1317f6960e3a0bf9dcc371613c98a6d7db701
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}
rule _#HSTR_PUA_Win32_Obfuse_27{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {4d 69 43 43 50 50 68 6f 74 6f 73 68 6f 70 20 49 43 43 20 70 72 6f 66 69 6c 65 } //1 MiCCPPhotoshop ICC profile
		$a_81_1 = {62 69 6e 61 72 69 65 73 5c 78 38 36 72 65 74 5c 62 69 6e 5c 69 33 38 36 5c 5c 6d 73 76 63 70 31 34 30 5f 32 2e 69 33 38 36 2e 70 64 62 } //1 binaries\x86ret\bin\i386\\msvcp140_2.i386.pdb
		$a_81_2 = {43 3a 5c 54 45 4d 50 5c 46 59 56 69 64 65 6f 43 6f 6e 76 65 72 74 65 72 5c 49 6e 73 74 61 6c 6c 45 78 65 2e 65 78 65 } //1 C:\TEMP\FYVideoConverter\InstallExe.exe
		$a_81_3 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 3a 20 22 25 73 22 20 28 25 64 29 } //1 CreateDirectory: "%s" (%d)
		$a_81_4 = {52 4d 44 69 72 3a 20 22 25 73 22 } //1 RMDir: "%s"
		$a_81_5 = {48 69 64 65 57 69 6e 64 6f 77 } //1 HideWindow
		$a_81_6 = {43 6f 70 79 46 69 6c 65 73 20 22 25 73 22 2d 3e 22 25 73 22 } //1 CopyFiles "%s"->"%s"
		$a_81_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 Software\Microsoft\Windows\CurrentVersion
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#HSTR_PUA_Win32_Obfuse_28{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 49 6e 73 74 61 6c 6c 44 65 74 61 69 6c 73 50 61 79 6c 6f 61 64 } //1 GetInstallDetailsPayload
		$a_81_1 = {49 73 42 72 6f 77 73 65 72 50 72 6f 63 65 73 73 } //1 IsBrowserProcess
		$a_81_2 = {49 73 45 78 74 65 6e 73 69 6f 6e 50 6f 69 6e 74 44 69 73 61 62 6c 65 53 65 74 } //1 IsExtensionPointDisableSet
		$a_81_3 = {53 69 67 6e 61 6c 43 68 72 6f 6d 65 45 6c 66 } //1 SignalChromeElf
		$a_81_4 = {53 69 67 6e 61 6c 49 6e 69 74 69 61 6c 69 7a 65 43 72 61 73 68 52 65 70 6f 72 74 69 6e 67 } //1 SignalInitializeCrashReporting
		$a_81_5 = {5c 63 68 72 6f 6d 69 75 6d 2d 62 72 6f 77 73 65 72 2d 73 63 72 69 70 74 73 5c 73 72 63 5c 6f 75 74 5c 52 65 6c 65 61 73 65 5c 69 6e 69 74 69 61 6c 65 78 65 5c 63 68 72 6f 6d 65 2e 65 78 65 2e 70 64 62 } //1 \chromium-browser-scripts\src\out\Release\initialexe\chrome.exe.pdb
		$a_81_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_7 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_8 = {63 68 72 6f 6d 65 5f 65 6c 66 2e 64 6c 6c } //1 chrome_elf.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule _#HSTR_PUA_Win32_Obfuse_29{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 58 43 45 45 44 45 44 20 4d 41 58 20 4e 55 4d 42 45 52 20 4f 46 20 4f 46 46 45 52 53 20 49 4e 20 46 4c 4f 57 } //1 EXCEEDED MAX NUMBER OF OFFERS IN FLOW
		$a_81_1 = {53 4b 49 50 20 41 4c 4c 20 41 46 54 45 52 20 44 45 43 4c 49 4e 45 20 4f 46 46 45 52 20 44 45 43 4c 49 4e 45 44 } //1 SKIP ALL AFTER DECLINE OFFER DECLINED
		$a_81_2 = {5c 44 53 2d 50 6c 61 74 66 6f 72 6d 5c 43 70 70 49 6e 73 74 61 6c 6c 65 72 5c 43 70 70 53 65 74 75 70 5c 62 69 6e 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 43 70 70 53 65 74 75 70 2e 70 64 62 } //1 \DS-Platform\CppInstaller\CppSetup\bin\Win32\Release\CppSetup.pdb
		$a_81_3 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_81_4 = {47 6c 6f 62 61 6c 41 6c 6c 6f 63 } //1 GlobalAlloc
		$a_81_5 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f } //1 GetStartupInfo
		$a_81_6 = {3c 57 45 4c 43 4f 4d 45 5f 54 45 58 54 3e 54 68 69 73 20 77 69 6c 6c 20 64 6f 77 6e 6c 6f 61 64 20 7b 50 52 4f 44 55 43 54 5f 54 49 54 4c 45 7d 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e } //1 <WELCOME_TEXT>This will download {PRODUCT_TITLE} on your computer.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_PUA_Win32_Obfuse_30{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 74 6f 75 63 68 5c 54 4f 55 43 48 } //1 \touch\TOUCH
		$a_81_1 = {2e 65 78 65 22 20 2f 52 65 67 53 65 72 76 65 72 } //1 .exe" /RegServer
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 43 4c 41 53 53 45 53 5c 2e 67 70 73 } //1 Software\CLASSES\.gps
		$a_81_3 = {47 4f 4d 4d 4f 44 55 4c 45 55 50 44 41 54 45 2e 45 58 45 } //1 GOMMODULEUPDATE.EXE
		$a_81_4 = {48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 HTTP\shell\open\command
		$a_81_5 = {41 70 70 58 71 30 66 65 76 7a 6d 65 32 70 79 73 36 32 6e 33 65 30 66 62 71 61 37 70 65 61 70 79 6b 72 38 76 } //1 AppXq0fevzme2pys62n3e0fbqa7peapykr8v
		$a_81_6 = {5c 46 69 6e 69 73 68 57 65 6c 63 6f 6d 65 2e 62 6d 70 } //1 \FinishWelcome.bmp
		$a_81_7 = {49 6e 73 74 61 6c 6c 65 72 20 63 6f 72 72 75 70 74 65 64 3a 20 69 6e 76 61 6c 69 64 20 6f 70 63 6f 64 65 } //1 Installer corrupted: invalid opcode
		$a_81_8 = {41 66 72 6f 77 20 53 6f 66 74 20 4c 74 64 } //1 Afrow Soft Ltd
		$a_81_9 = {42 75 74 74 6f 6e 45 76 65 6e 74 20 44 79 6e 61 6d 69 63 20 4c 69 6e 6b 20 4c 69 62 72 61 72 79 } //1 ButtonEvent Dynamic Link Library
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}
rule _#HSTR_PUA_Win32_Obfuse_31{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 76 69 73 69 74 2e 6b 65 79 67 75 61 72 64 61 69 2e 63 6f 6d 2f 63 6c 69 63 6b } //1 https://visit.keyguardai.com/click
		$a_81_1 = {5a 47 39 33 62 6d 78 76 59 57 52 66 59 6e 4a 76 64 33 4e 6c 63 67 3d 3d } //1 ZG93bmxvYWRfYnJvd3Nlcg==
		$a_03_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-0a] 2e 00 74 00 68 00 69 00 73 00 69 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 } //1
		$a_03_3 = {68 74 74 70 73 3a 2f 2f [0-0a] 2e 74 68 69 73 69 6c 69 65 6e 74 2e 63 6f 6d } //1
		$a_81_4 = {5c 5a 69 70 54 68 69 73 41 70 70 2e 6c 6e 6b } //1 \ZipThisApp.lnk
		$a_81_5 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 7a 69 70 74 68 69 73 61 70 70 2e 63 6f 6d 2f 73 75 63 63 65 73 73 } //1 https://www.zipthisapp.com/success
		$a_81_6 = {75 70 64 61 74 65 5f 74 61 73 6b 5f 61 64 2e 70 73 31 } //1 update_task_ad.ps1
		$a_81_7 = {75 70 64 61 74 65 5f 74 61 73 6b 2e 70 73 31 } //1 update_task.ps1
		$a_81_8 = {5c 5a 69 70 54 68 69 73 41 70 70 2e 65 78 65 } //1 \ZipThisApp.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}
rule _#HSTR_PUA_Win32_Obfuse_32{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {44 6f 63 75 6d 65 6e 74 73 20 53 75 67 67 65 73 74 20 52 75 73 73 69 61 20 54 72 69 65 64 20 74 6f 20 41 74 74 61 63 6b 20 55 53 20 56 6f 74 65 72 20 52 65 67 69 73 74 72 61 74 69 6f 6e 20 52 65 63 6f 72 64 73 2e 74 78 74 } //1 Documents Suggest Russia Tried to Attack US Voter Registration Records.txt
		$a_81_1 = {45 78 70 65 72 74 73 20 45 78 61 6d 69 6e 65 20 4c 69 6e 6b 73 20 42 65 74 77 65 65 6e 20 42 72 61 69 6e 20 49 6e 6a 75 72 69 65 73 20 61 6e 64 20 41 6d 65 72 69 63 61 6e 20 46 6f 6f 74 62 61 6c 6c 2e 74 78 74 } //1 Experts Examine Links Between Brain Injuries and American Football.txt
		$a_81_2 = {6f 72 61 6e 67 65 5c 67 61 6d 65 73 5c 67 61 6d 65 34 2e 68 74 6d } //1 orange\games\game4.htm
		$a_81_3 = {57 65 62 73 69 74 65 2e 6c 6e 6b } //1 Website.lnk
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {54 79 70 65 52 75 6e } //1 TypeRun
		$a_81_6 = {53 65 6c 66 44 65 6c 2e 64 6c 6c } //1 SelfDel.dll
		$a_81_7 = {36 35 42 37 30 44 45 37 35 34 30 43 34 32 37 35 39 31 35 36 34 38 33 31 36 35 45 33 35 32 31 35 } //1 65B70DE7540C42759156483165E35215
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#HSTR_PUA_Win32_Obfuse_33{
	meta:
		description = "!#HSTR:PUA:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0b 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 73 73 2e 73 68 61 6e 68 75 74 65 63 68 2e 63 6e 2f 75 72 6c 33 3f } //1 http://ss.shanhutech.cn/url3?
		$a_81_1 = {68 74 74 70 3a 2f 2f 73 73 2e 64 69 64 61 70 61 70 65 72 2e 63 6f 6d 2f 64 6f 74 3f } //1 http://ss.didapaper.com/dot?
		$a_81_2 = {68 74 74 70 3a 2f 2f 73 73 2e 79 69 6e 67 79 61 6e 6b 61 6e 74 75 2e 63 6f 6d 2f 64 6f 74 3f } //1 http://ss.yingyankantu.com/dot?
		$a_81_3 = {68 74 74 70 3a 2f 2f 73 73 2e 67 6f 6f 64 73 65 65 70 69 63 2e 63 6f 6d 2f 64 6f 74 3f } //1 http://ss.goodseepic.com/dot?
		$a_81_4 = {68 74 74 70 3a 2f 2f 73 73 2e 64 6f 6c 70 68 69 6e 70 61 70 65 72 2e 63 6f 6d 2f 64 6f 74 3f } //1 http://ss.dolphinpaper.com/dot?
		$a_81_5 = {68 74 74 70 3a 2f 2f 73 73 2e 68 61 6c 6f 70 61 70 65 72 2e 63 6e 2f 64 6f 74 3f } //1 http://ss.halopaper.cn/dot?
		$a_81_6 = {68 74 74 70 3a 2f 2f 73 73 2e 63 63 6d 6f 75 73 65 2e 63 6f 6d 2f 64 6f 74 3f } //1 http://ss.ccmouse.com/dot?
		$a_81_7 = {68 74 74 70 3a 2f 2f 73 73 2e 77 68 61 6c 65 70 72 6f 74 65 63 74 2e 63 6e 2f 64 6f 74 3f } //1 http://ss.whaleprotect.cn/dot?
		$a_81_8 = {68 74 74 70 3a 2f 2f 73 73 2e 62 6c 75 65 77 68 61 6c 65 63 68 61 74 2e 63 6f 6d 2f 64 6f 74 3f } //1 http://ss.bluewhalechat.com/dot?
		$a_81_9 = {68 74 74 70 3a 2f 2f 73 73 2e 70 63 6a 69 61 6d 69 2e 63 6e 2f 64 6f 74 3f } //1 http://ss.pcjiami.cn/dot?
		$a_81_10 = {68 74 74 70 3a 2f 2f 73 73 2e 68 61 6c 6f 70 65 74 2e 63 6e 2f 64 6f 74 3f } //1 http://ss.halopet.cn/dot?
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=6
 
}