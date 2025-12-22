
rule HackTool_Win32_Patcher_AMTB{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 69 61 4c 6f 67 2a 65 7a 74 } //1 DiaLog*ezt
		$a_01_1 = {78 78 50 7a 72 67 6d 7a } //1 xxPzrgmz
		$a_01_2 = {4e 47 20 50 72 61 63 6b 77 3e 34 49 64 40 2d } //1 NG Prackw>4Id@-
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=3
 
}
rule HackTool_Win32_Patcher_AMTB_2{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 74 00 63 00 68 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 54 00 6f 00 6c 00 61 00 27 00 73 00 20 00 50 00 61 00 74 00 63 00 68 00 69 00 6e 00 67 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 } //1 Patch created by Tola's Patching Engine
		$a_80_1 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_2 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_3 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
		$a_80_4 = {4d 75 6c 74 69 45 78 74 72 61 63 74 6f 72 2e 65 78 65 } //MultiExtractor.exe  -100
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*-100+(#a_80_2  & 1)*-100+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100) >=1
 
}