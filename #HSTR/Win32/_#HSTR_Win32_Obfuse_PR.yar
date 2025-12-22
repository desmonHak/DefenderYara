
rule _#HSTR_Win32_Obfuse_PR{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 ca 49 c1 e1 20 4c 0b c9 49 8b c9 45 88 0c 03 48 c1 e9 [0-02] 41 88 4c 03 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#HSTR_Win32_Obfuse_PR_2{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6c 6f 63 61 6c 68 6f 73 74 2f 77 33 73 76 63 } //1 localhost/w3svc
		$a_81_1 = {43 3a 5c 69 6e 65 74 70 75 62 5c 69 6e 6e 6f 73 65 74 75 70 } //1 C:\inetpub\innosetup
		$a_81_2 = {68 74 74 70 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 32 72 75 77 33 64 61 6b } //1 http://tinyurl.com/2ruw3dak
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule _#HSTR_Win32_Obfuse_PR_3{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6d 61 63 65 78 } //1 macex
		$a_81_1 = {66 72 65 73 68 43 61 6b 65 2e 64 6c 6c } //1 freshCake.dll
		$a_81_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_3 = {56 69 72 74 75 61 6c 46 72 65 65 } //1 VirtualFree
		$a_81_4 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_Win32_Obfuse_PR_4{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 75 74 6f 63 61 6c 63 77 69 64 74 68 } //1 autocalcwidth
		$a_81_1 = {57 69 6e 55 70 64 61 74 65 2e 65 78 65 } //1 WinUpdate.exe
		$a_81_2 = {68 74 74 70 3a 2f 2f 77 69 6e 2e 35 35 6b 61 6e 74 75 2e 63 6f 6d 2f } //1 http://win.55kantu.com/
		$a_81_3 = {41 62 6f 75 74 2e 65 78 65 } //1 About.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule _#HSTR_Win32_Obfuse_PR_5{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_1 = {58 63 76 44 61 74 61 57 } //1 XcvDataW
		$a_81_2 = {43 72 61 63 6b 2e 78 78 64 } //1 Crack.xxd
		$a_81_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_81_4 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_Win32_Obfuse_PR_6{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 79 70 74 4f 70 65 6e 41 6c 67 6f 72 69 38 30 } //1 ryptOpenAlgori80
		$a_81_1 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_81_2 = {62 65 64 61 73 68 2e 64 6c 6c } //1 bedash.dll
		$a_81_3 = {70 65 70 69 6e 65 6c 6c 61 2e 64 6c 6c } //1 pepinella.dll
		$a_81_4 = {65 6e 64 6f 67 6e 61 74 68 69 6f 6e } //1 endognathion
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_Win32_Obfuse_PR_7{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 79 6e 74 61 6b 73 61 6e 61 6c 79 73 65 72 6e 65 20 63 6f 64 65 76 65 6c 6f 70 } //1 syntaksanalyserne codevelop
		$a_81_1 = {68 61 65 72 76 61 65 72 6b 20 70 65 6e 64 61 6e 74 65 72 } //1 haervaerk pendanter
		$a_81_2 = {73 6d 69 74 73 6f 6d 6d 65 73 74 65 20 72 64 6c 65 72 65 74 73 } //1 smitsommeste rdlerets
		$a_81_3 = {6d 6f 6e 6f 6e 69 74 72 69 64 65 20 66 69 73 6b 65 6b 75 74 74 65 72 20 69 6e 6a 65 63 74 73 } //1 mononitride fiskekutter injects
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}
rule _#HSTR_Win32_Obfuse_PR_8{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 72 75 6e 6e 65 72 61 64 6d 69 6e 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 70 6b 67 2e 64 37 63 36 61 31 30 66 62 30 32 36 33 61 36 39 62 34 35 39 36 33 32 31 5c 6e 6f 64 65 5c } //1 C:\Users\runneradmin\AppData\Local\Temp\pkg.d7c6a10fb0263a69b4596321\node\
		$a_81_1 = {47 79 4d 64 6b 48 6d 73 53 45 44 46 77 57 61 68 4b 7a 59 65 75 67 41 5a 76 63 4c 51 71 56 55 4f 58 78 72 62 42 } //1 GyMdkHmsSEDFwWahKzYeugAZvcLQqVUOXxrbB
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule _#HSTR_Win32_Obfuse_PR_9{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {64 65 6c 65 74 65 5b 5d } //1 delete[]
		$a_81_1 = {5c 49 6e 74 65 6c 6c 69 53 70 61 63 65 50 41 43 53 4d 65 64 69 61 56 69 65 77 65 72 2e 65 78 65 } //1 \IntelliSpacePACSMediaViewer.exe
		$a_81_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_3 = {43 6f 70 79 46 69 6c 65 } //1 CopyFile
		$a_81_4 = {53 6c 65 65 70 } //1 Sleep
		$a_81_5 = {50 68 69 6c 69 70 73 20 4d 65 64 69 61 20 56 69 65 77 65 72 20 4c 61 75 6e 63 68 65 72 } //1 Philips Media Viewer Launcher
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_Win32_Obfuse_PR_10{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_1 = {53 6c 65 65 70 } //1 Sleep
		$a_81_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //1 GetTickCount64
		$a_81_3 = {47 6c 6f 62 61 6c 4d 65 6d 6f 72 79 53 74 61 74 75 73 } //1 GlobalMemoryStatus
		$a_81_4 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_5 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f } //1 GetStartupInfo
		$a_81_6 = {64 6c 6c 68 6f 73 74 70 67 64 2e 65 78 65 } //1 dllhostpgd.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_Win32_Obfuse_PR_11{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4a 4c 5a 4d 41 44 65 63 6f 6d 70 53 6d 61 6c 6c } //1 JLZMADecompSmall
		$a_81_1 = {6e 30 30 30 31 30 32 30 33 30 34 30 35 30 36 30 37 30 38 30 39 31 30 31 31 31 32 31 33 31 34 31 35 31 36 31 37 31 38 31 39 32 30 32 31 } //1 n00010203040506070809101112131415161718192021
		$a_81_2 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 2e } //1 This installation was built with Inno Setup.
		$a_81_3 = {45 70 73 69 6c 6f 6e 20 4d 65 6e 75 2e 65 78 65 20 20 20 } //1 Epsilon Menu.exe   
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule _#HSTR_Win32_Obfuse_PR_12{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 70 74 42 72 6f 77 73 65 72 2e 65 78 65 } //1 GptBrowser.exe
		$a_81_1 = {49 73 53 61 6e 64 62 6f 78 65 64 50 72 6f 63 65 73 73 } //1 IsSandboxedProcess
		$a_81_2 = {53 6c 65 65 70 } //1 Sleep
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_4 = {2e 5c 70 69 70 65 5c 6d 6f 6a 6f 2e 25 6c 75 2e 25 6c 75 2e 25 } //1 .\pipe\mojo.%lu.%lu.%
		$a_81_5 = {49 6d 70 6c 69 63 69 74 41 70 70 53 68 6f 72 74 63 75 74 73 } //1 ImplicitAppShortcuts
		$a_81_6 = {43 68 72 6f 6d 65 5f 4d 65 73 73 61 67 65 57 69 6e 64 6f 77 } //1 Chrome_MessageWindow
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_Win32_Obfuse_PR_13{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_1 = {50 6f 77 65 72 53 68 65 6c 6c } //1 PowerShell
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_5 = {5a 6a 41 74 4f 54 59 34 4e 53 31 6d 5a 6a 56 69 59 6a 49 32 4d 47 52 6d 4d 6d 55 67 4e 47 59 35 4e 7a 46 6c 4f 44 6b 74 } //1 ZjAtOTY4NS1mZjViYjI2MGRmMmUgNGY5NzFlODkt
		$a_81_6 = {4f 57 59 74 59 54 49 33 59 69 30 30 4e 7a 5a 69 4d 57 51 77 4d 57 4d 35 4d 7a 59 67 4d 53 49 3d } //1 OWYtYTI3Yi00NzZiMWQwMWM5MzYgMSI=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_Win32_Obfuse_PR_14{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {43 6f 72 65 68 6f 73 74 2e 53 74 61 74 69 63 5c 73 69 6e 67 6c 65 66 69 6c 65 68 6f 73 74 2e 70 64 62 } //1 Corehost.Static\singlefilehost.pdb
		$a_81_1 = {2e 43 4c 52 5f 55 45 46 } //1 .CLR_UEF
		$a_81_2 = {2e 64 69 64 61 74 24 } //1 .didat$
		$a_81_3 = {5f 52 44 41 54 41 } //1 _RDATA
		$a_81_4 = {53 6c 65 65 70 } //1 Sleep
		$a_81_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_6 = {56 69 72 74 75 61 6c 46 72 65 65 } //1 VirtualFree
		$a_81_7 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_8 = {54 65 6c 65 73 74 6f 53 74 61 72 74 75 70 45 76 65 6e 74 } //1 TelestoStartupEvent
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule _#HSTR_Win32_Obfuse_PR_15{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 7a 65 6e 5c 66 69 6c 65 5f 61 63 63 65 73 73 2e 63 70 70 } //1 \zen\file_access.cpp
		$a_81_1 = {65 78 69 73 74 20 69 6e 20 74 68 69 73 20 64 69 72 65 63 74 6f 72 79 3f 20 59 6f 75 27 72 65 20 6b 69 64 64 69 6e 67 } //1 exist in this directory? You're kidding
		$a_81_2 = {5c 7a 65 6e 5c 7a 73 74 72 69 6e 67 2e 63 70 70 } //1 \zen\zstring.cpp
		$a_81_3 = {5c 42 75 69 6c 64 5c 42 69 6e 5c 52 65 61 6c 74 69 6d 65 53 79 6e 63 5f 78 36 34 2e 70 64 62 } //1 \Build\Bin\RealtimeSync_x64.pdb
		$a_81_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule _#HSTR_Win32_Obfuse_PR_16{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {47 6c 6f 62 61 6c 41 6c 6c 6f 63 } //1 GlobalAlloc
		$a_81_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_81_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_3 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
		$a_81_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 53 74 65 61 6d 5c 4c 61 75 6e 63 68 65 72 } //1 C:\ProgramData\Steam\Launcher
		$a_81_5 = {43 6f 70 79 20 74 6f } //1 Copy to
		$a_81_6 = {53 74 65 61 6d 20 53 65 74 75 70 } //1 Steam Setup
		$a_81_7 = {56 61 6c 76 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Valve Corporation
		$a_81_8 = {53 74 65 61 6d } //1 Steam
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule _#HSTR_Win32_Obfuse_PR_17{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {74 69 6e 39 39 39 39 2e 74 6d 70 } //1 tin9999.tmp
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_81_2 = {54 68 69 73 20 61 72 63 68 69 76 65 20 69 73 20 63 6f 72 72 75 70 74 65 64 } //1 This archive is corrupted
		$a_81_3 = {5b 41 70 70 44 61 74 61 46 6f 6c 64 65 72 5d 4d 61 64 65 49 6e 43 5c 4d 61 6b 61 72 6f 6e 69 5c 70 72 65 72 65 71 75 69 73 69 74 65 73 } //1 [AppDataFolder]MadeInC\Makaroni\prerequisites
		$a_81_4 = {2f 66 6f 72 63 65 63 6c 65 61 6e 75 70 20 20 2f 77 69 6e 74 69 6d 65 20 } //1 /forcecleanup  /wintime 
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#HSTR_Win32_Obfuse_PR_18{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {57 44 43 4c 45 41 4e 2e 45 58 45 } //1 WDCLEAN.EXE
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 25 73 2e 65 78 65 } //1 Software\Microsoft\Windows\CurrentVersion\App Paths\%s.exe
		$a_81_2 = {53 49 4c 45 4e 54 } //1 SILENT
		$a_81_3 = {52 45 4c 41 4e 43 45 } //1 RELANCE
		$a_81_4 = {5a 49 50 5f 53 4f 55 52 43 45 } //1 ZIP_SOURCE
		$a_81_5 = {49 4e 46 4f 57 44 5a } //1 INFOWDZ
		$a_81_6 = {53 3a 5c 54 68 65 46 6c 65 78 5c 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 5c 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 54 68 65 46 6c 65 78 2e 65 78 65 } //1 S:\TheFlex\Installation\InstallationTheFlex.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_Win32_Obfuse_PR_19{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 } //1 DisableThreadLibraryCalls
		$a_81_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_2 = {52 65 67 4f 72 67 61 6e 69 7a 65 72 2e 65 78 65 } //1 RegOrganizer.exe
		$a_81_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 76 65 72 73 69 6f 6e 2e 64 6c 6c } //1 C:\WINDOWS\SYSTEM32\version.dll
		$a_81_4 = {57 41 52 45 5a 44 2d 4f 57 4e 46 4f 52 2d 46 4f 52 55 4d 52 2d 55 42 4f 41 52 44 2d 43 4f 4d 49 4e 43 2d 52 41 43 4b 57 45 2d 54 52 55 53 54 57 2d 41 52 45 5a 44 4f 2d 57 4e 57 44 } //1 WAREZD-OWNFOR-FORUMR-UBOARD-COMINC-RACKWE-TRUSTW-AREZDO-WNWD
		$a_81_5 = {57 61 72 65 7a 5f 44 6f 77 6e } //1 Warez_Down
		$a_81_6 = {50 72 6f 78 79 20 44 4c 4c } //1 Proxy DLL
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_Win32_Obfuse_PR_20{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 6f 64 65 50 6f 69 6e 74 65 72 } //1 DecodePointer
		$a_81_1 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
		$a_81_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {52 74 6c 50 63 54 6f 46 69 6c 65 48 65 61 64 65 72 } //1 RtlPcToFileHeader
		$a_81_5 = {68 6f 73 74 66 78 72 5f 6d 61 69 6e 5f 73 74 61 72 74 75 70 69 6e 66 6f } //1 hostfxr_main_startupinfo
		$a_81_6 = {64 6f 65 73 20 6e 6f 74 20 63 6f 6e 74 61 69 6e 20 74 68 65 20 65 78 70 65 63 74 65 64 20 65 6e 74 72 79 20 70 6f 69 6e 74 2e } //1 does not contain the expected entry point.
		$a_81_7 = {43 56 45 2d 32 30 32 33 2d 32 37 35 33 32 } //1 CVE-2023-27532
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#HSTR_Win32_Obfuse_PR_21{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 75 75 66 30 63 42 46 78 51 41 77 76 6d 35 5a 33 35 6f 47 54 4f 53 6d 46 35 55 35 57 6c 58 71 6b 35 32 76 57 } //1 huuf0cBFxQAwvm5Z35oGTOSmF5U5WlXqk52vW
		$a_81_1 = {53 53 4a 56 72 6f 32 68 61 67 48 70 71 42 63 7a 56 57 63 73 77 42 7a } //1 SSJVro2hagHpqBczVWcswBz
		$a_81_2 = {55 49 73 62 69 53 37 64 37 37 46 4e 78 39 65 65 4d 41 75 6f 77 51 4d 4f 4d 61 4d 35 4e 42 4d 73 34 49 72 4c 42 5a } //1 UIsbiS7d77FNx9eeMAuowQMOMaM5NBMs4IrLBZ
		$a_81_3 = {42 46 6f 6a 6b 35 65 5a 38 58 4b 64 78 53 64 62 37 78 6f 42 43 50 49 42 77 4b 79 6d 70 4a 32 51 3d 3d } //1 BFojk5eZ8XKdxSdb7xoBCPIBwKympJ2Q==
		$a_81_4 = {61 74 6c 6d 66 63 5c 69 6e 63 6c 75 64 65 5c 61 66 78 77 69 6e 31 2e 69 6e 6c } //1 atlmfc\include\afxwin1.inl
		$a_81_5 = {43 6c 69 70 56 69 65 77 2e 70 64 62 } //1 ClipView.pdb
		$a_81_6 = {43 6c 69 70 56 69 65 77 2e 65 78 65 } //1 ClipView.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_Win32_Obfuse_PR_22{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {49 73 6f 6c 61 74 65 64 43 6f 6d 70 6f 6e 65 6e 74 } //1 IsolatedComponent
		$a_81_1 = {41 45 53 20 44 65 63 72 79 70 74 } //1 AES Decrypt
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 72 65 73 6f 75 72 63 65 20 66 69 6c 65 73 20 61 72 63 68 69 76 65 2e 2e 2e } //1 Downloading resource files archive...
		$a_81_3 = {43 3a 5c 50 72 6f 66 79 55 73 65 2e 6d 73 69 } //1 C:\ProfyUse.msi
		$a_81_4 = {44 65 6c 65 74 69 6e 67 20 65 78 74 72 61 63 74 65 64 20 66 69 6c 65 73 2e 2e 2e } //1 Deleting extracted files...
		$a_81_5 = {45 58 45 5f 43 4d 44 5f 4c 49 4e 45 3d 22 2f 66 6f 72 63 65 63 6c 65 61 6e 75 70 20 20 2f 77 69 6e 74 69 6d 65 } //1 EXE_CMD_LINE="/forcecleanup  /wintime
		$a_81_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#HSTR_Win32_Obfuse_PR_23{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 65 67 44 65 6c 65 74 65 2c 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 2c 20 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 2c 20 53 74 61 72 74 54 6f 6f 6c 73 } //1 RegDelete, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Run, StartTools
		$a_81_1 = {55 72 6c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 UrlDownloadToFile
		$a_81_2 = {49 6e 69 72 65 61 64 2c 20 50 75 74 54 6f 6f 6c 73 2c 20 25 41 5f 41 70 70 44 61 74 61 25 5c 41 72 69 7a 6f 6e 61 54 6f 6f 6c 73 2e 73 74 61 72 74 2c 20 4f 75 74 50 75 74 2c 20 50 75 74 54 6f 6f 6c 73 } //1 Iniread, PutTools, %A_AppData%\ArizonaTools.start, OutPut, PutTools
		$a_81_3 = {49 66 4e 6f 74 45 78 69 73 74 2c 20 25 41 5f 41 70 70 44 61 74 61 25 5c 6c 6f 61 64 69 6e 67 61 74 6f 6f 6c 73 2e 6d 70 34 } //1 IfNotExist, %A_AppData%\loadingatools.mp4
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule _#HSTR_Win32_Obfuse_PR_24{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 71 69 79 75 6a 69 61 73 75 2e 63 6f 6d 2f } //1 http://update.qiyujiasu.com/
		$a_81_1 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 74 61 6f 6a 69 6b 65 2e 63 6f 6d 2e 63 6e 2f } //1 http://update.taojike.com.cn/
		$a_81_2 = {43 6f 75 70 6f 6e 62 6f 78 2e 65 78 65 } //1 Couponbox.exe
		$a_81_3 = {48 61 6c 6f 44 65 73 6b 74 6f 70 2e 65 78 65 } //1 HaloDesktop.exe
		$a_81_4 = {42 69 6e 5c 33 36 30 44 65 73 6b 74 6f 70 2e 65 78 65 } //1 Bin\360Desktop.exe
		$a_81_5 = {59 78 68 47 61 6d 65 76 65 72 2e 64 6c 6c } //1 YxhGamever.dll
		$a_81_6 = {4c 65 79 6f 75 47 61 6d 65 76 65 72 2e 64 6c 6c } //1 LeyouGamever.dll
		$a_81_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 33 36 30 77 70 61 70 70 2e 65 78 65 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\360wpapp.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#HSTR_Win32_Obfuse_PR_25{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion
		$a_81_1 = {54 68 65 20 73 65 74 75 70 20 66 69 6c 65 73 20 61 72 65 20 63 6f 72 72 75 70 74 65 64 2e 20 50 6c 65 61 73 65 20 6f 62 74 61 69 6e 20 61 20 6e 65 77 20 63 6f 70 79 20 6f 66 20 74 68 65 20 70 72 6f 67 72 61 6d 2e } //1 The setup files are corrupted. Please obtain a new copy of the program.
		$a_81_2 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 2e } //1 This installation was built with Inno Setup.
		$a_81_3 = {57 6f 77 36 34 44 69 73 61 62 6c 65 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e } //1 Wow64DisableWow64FsRedirection
		$a_81_4 = {57 6f 77 36 34 52 65 76 65 72 74 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e } //1 Wow64RevertWow64FsRedirection
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}
rule _#HSTR_Win32_Obfuse_PR_26{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {55 6e 6b 6f 77 6e 43 50 55 } //1 UnkownCPU
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {68 74 74 70 73 3a 2f 2f } //1 https://
		$a_81_3 = {52 65 6d 6f 76 65 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 } //1 RemoveEnvironmentStrings
		$a_81_4 = {52 65 6d 6f 76 65 46 69 6c 65 73 } //1 RemoveFiles
		$a_81_5 = {43 6f 70 79 20 55 52 4c 20 49 6e 20 43 6c 69 70 62 6f 61 72 64 } //1 Copy URL In Clipboard
		$a_81_6 = {41 45 53 20 44 65 63 72 79 70 74 } //1 AES Decrypt
		$a_81_7 = {44 65 6c 65 74 69 6e 67 20 65 78 74 72 61 63 74 65 64 20 66 69 6c 65 73 2e 2e 2e } //1 Deleting extracted files...
		$a_81_8 = {43 61 6e 63 65 6c 2b 44 6f 77 6e 6c 6f 61 64 65 64 20 66 69 6c 65 20 64 6f 65 73 20 6e 6f 74 20 68 61 76 65 20 65 78 70 65 63 74 65 64 20 73 69 7a 65 } //1 Cancel+Downloaded file does not have expected size
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule _#HSTR_Win32_Obfuse_PR_27{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
		$a_81_1 = {24 7b 52 45 44 49 53 54 5f 54 45 4d 50 5f 44 49 52 7d 5c 76 63 72 65 64 69 73 74 5f 78 38 36 2e 65 78 65 22 20 2f 69 6e 73 74 61 6c 6c 20 2f 71 75 69 65 74 20 2f 6e 6f 72 65 73 74 61 72 74 } //1 ${REDIST_TEMP_DIR}\vcredist_x86.exe" /install /quiet /norestart
		$a_81_2 = {65 72 72 6f 72 45 78 74 72 61 63 74 44 4c 4c 54 65 6d 70 44 69 72 } //1 errorExtractDLLTempDir
		$a_03_3 = {74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 5c 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 5c 00 [0-14] 74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1
		$a_03_4 = {74 6f 72 72 65 6e 74 5c 75 70 64 61 74 65 73 5c [0-14] 74 6f 72 72 65 6e 74 2e 65 78 65 } //1
		$a_81_5 = {65 72 72 6f 72 43 6f 70 79 44 4c 4c 44 69 72 55 70 64 61 74 65 } //1 errorCopyDLLDirUpdate
		$a_81_6 = {63 6c 65 61 6e 49 6e 73 74 61 6c 6c } //1 cleanInstall
		$a_81_7 = {41 26 63 65 70 74 6f } //1 A&cepto
		$a_81_8 = {2f 53 49 4c 45 4e 54 } //1 /SILENT
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}
rule _#HSTR_Win32_Obfuse_PR_28{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {53 6c 65 65 70 } //1 Sleep
		$a_81_1 = {43 61 6e 63 65 6c } //1 Cancel
		$a_81_2 = {56 61 72 69 61 6e 74 43 6c 65 61 72 } //1 VariantClear
		$a_81_3 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_5 = {72 75 73 74 5f 70 61 6e 69 63 } //1 rust_panic
		$a_81_6 = {64 69 72 65 63 74 69 6e 73 74 61 6c 6c } //1 directinstall
		$a_81_7 = {4e 65 74 41 70 69 42 75 66 66 65 72 46 72 65 65 } //1 NetApiBufferFree
		$a_81_8 = {4e 65 74 55 73 65 72 47 65 74 49 6e 66 6f } //1 NetUserGetInfo
		$a_81_9 = {41 63 71 75 69 72 65 43 72 65 64 65 6e 74 69 61 6c 73 48 61 6e 64 6c 65 } //1 AcquireCredentialsHandle
		$a_81_10 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } //1 DecryptMessage
		$a_81_11 = {44 65 6c 65 74 65 53 65 63 75 72 69 74 79 43 6f 6e 74 65 78 74 } //1 DeleteSecurityContext
		$a_81_12 = {45 6e 63 72 79 70 74 4d 65 73 73 61 67 65 } //1 EncryptMessage
		$a_81_13 = {46 72 65 65 43 72 65 64 65 6e 74 69 61 6c 73 48 61 6e 64 6c 65 } //1 FreeCredentialsHandle
		$a_81_14 = {4c 73 61 45 6e 75 6d 65 72 61 74 65 4c 6f 67 6f 6e 53 65 73 73 69 6f 6e 73 } //1 LsaEnumerateLogonSessions
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}
rule _#HSTR_Win32_Obfuse_PR_29{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {54 49 6e 74 65 72 6e 61 6c 45 72 61 49 6e 66 6f 52 65 63 6f 72 64 } //1 TInternalEraInfoRecord
		$a_81_1 = {57 69 6e 61 70 69 2e 49 70 45 78 70 6f 72 74 } //1 Winapi.IpExport
		$a_81_2 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f } //1 GetStartupInfo
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_4 = {43 6f 6e 76 65 72 74 53 69 64 54 6f 53 74 72 69 6e 67 53 69 64 } //1 ConvertSidToStringSid
		$a_81_5 = {5f 5f 64 62 6b 5f 66 63 61 6c 6c 5f 77 72 61 70 70 65 72 } //1 __dbk_fcall_wrapper
		$a_81_6 = {64 62 6b 46 43 61 6c 6c 57 72 61 70 70 65 72 41 64 64 72 } //1 dbkFCallWrapperAddr
		$a_81_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion
		$a_81_8 = {57 6f 77 36 34 44 69 73 61 62 6c 65 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e } //1 Wow64DisableWow64FsRedirection
		$a_81_9 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 2e } //1 This installation was built with Inno Setup.
		$a_81_10 = {56 61 72 69 61 6e 74 43 6f 70 79 } //1 VariantCopy
		$a_81_11 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 } //1 CallWindowProc
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}
rule _#HSTR_Win32_Obfuse_PR_30{
	meta:
		description = "!#HSTR:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 "
		
	strings :
		$a_81_0 = {6b 65 72 6e 65 6c 33 32 3a 3a 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 kernel32::GetCurrentProcess
		$a_81_1 = {6b 65 72 6e 65 6c 33 32 3a 3a 49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 32 } //1 kernel32::IsWow64Process2
		$a_81_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_4 = {5c 32 62 56 69 59 34 49 75 50 30 38 78 42 45 36 61 77 65 73 36 75 63 52 30 51 7a 76 } //1 \2bViY4IuP08xBE6awes6ucR0Qzv
		$a_81_5 = {5c 32 5a 5a 6a 46 7a 4c 6b 79 75 44 41 47 30 78 42 69 69 54 66 71 54 4f 32 4c 69 39 } //1 \2ZZjFzLkyuDAG0xBiiTfqTO2Li9
		$a_81_6 = {5c 37 7a 2d 6f 75 74 5c } //1 \7z-out\
		$a_03_7 = {43 00 61 00 6e 00 27 00 74 00 20 00 6d 00 6f 00 64 00 69 00 66 00 79 00 20 00 22 00 [0-64] 22 00 27 00 73 00 20 00 66 00 69 00 6c 00 65 00 73 00 } //1
		$a_03_8 = {43 61 6e 27 74 20 6d 6f 64 69 66 79 20 22 [0-64] 22 27 73 20 66 69 6c 65 73 } //1
		$a_03_9 = {4b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 3a 00 3a 00 53 00 65 00 74 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 28 00 74 00 2c 00 20 00 74 00 29 00 69 00 20 00 28 00 22 00 50 00 4f 00 52 00 54 00 41 00 42 00 4c 00 45 00 5f 00 45 00 58 00 45 00 43 00 55 00 54 00 41 00 42 00 4c 00 45 00 5f 00 41 00 50 00 50 00 5f 00 46 00 49 00 4c 00 45 00 4e 00 41 00 4d 00 45 00 22 00 2c 00 20 00 22 00 [0-20] 22 00 29 00 2e 00 72 00 30 00 } //1
		$a_03_10 = {4b 65 72 6e 65 6c 33 32 3a 3a 53 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 28 74 2c 20 74 29 69 20 28 22 50 4f 52 54 41 42 4c 45 5f 45 58 45 43 55 54 41 42 4c 45 5f 41 50 50 5f 46 49 4c 45 4e 41 4d 45 22 2c 20 22 [0-20] 22 29 2e 72 30 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1) >=8
 
}