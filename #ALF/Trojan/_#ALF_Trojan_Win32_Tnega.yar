
rule _#ALF_Trojan_Win32_Tnega{
	meta:
		description = "!#ALF:Trojan:Win32/Tnega!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 75 70 31 31 32 2e 65 78 65 } //1 sup112.exe
		$a_01_1 = {73 75 70 31 31 33 2e 74 6d 70 } //1 sup113.tmp
		$a_01_2 = {6e 65 74 20 73 74 61 72 74 } //1 net start
		$a_01_3 = {64 72 65 61 6b 65 72 5f 77 69 6e 2e 70 64 62 } //1 dreaker_win.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#ALF_Trojan_Win32_Tnega_2{
	meta:
		description = "!#ALF:Trojan:Win32/Tnega!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {74 69 6d 65 6f 75 74 20 28 73 65 63 29 } //timeout (sec)  1
		$a_80_1 = {45 72 72 6f 72 20 73 65 6e 64 69 6e 67 20 63 6c 6f 73 65 20 6d 65 73 73 61 67 65 } //Error sending close message  1
		$a_80_2 = {43 6c 6f 73 65 20 6d 65 73 73 61 67 65 20 73 65 6e 74 } //Close message sent  1
		$a_80_3 = {63 6c 6f 73 65 77 6e 64 2e 70 64 62 } //closewnd.pdb  1
		$a_80_4 = {63 6c 6f 73 65 77 6e 64 2e 65 78 65 } //closewnd.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#ALF_Trojan_Win32_Tnega_3{
	meta:
		description = "!#ALF:Trojan:Win32/Tnega!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {39 30 2e 79 61 79 6f 75 2e 7a 68 63 67 6a 38 38 38 2e 63 6f 6d 2f 67 75 61 6a 69 52 4d 2f 67 75 61 6a 69 2f } //1 90.yayou.zhcgj888.com/guajiRM/guaji/
		$a_81_1 = {67 75 61 6a 69 52 4d } //1 guajiRM
		$a_81_2 = {55 70 64 61 74 65 5c 41 75 74 6f 55 70 64 61 74 65 50 6c 75 73 2e 65 78 65 } //1 Update\AutoUpdatePlus.exe
		$a_81_3 = {4b 69 6c 6c 41 70 70 46 69 6c 65 } //1 KillAppFile
		$a_81_4 = {44 3a 5c 7a 68 63 5f 6e 65 77 32 5c 73 74 61 72 74 75 70 5c 57 44 } //1 D:\zhc_new2\startup\WD
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule _#ALF_Trojan_Win32_Tnega_4{
	meta:
		description = "!#ALF:Trojan:Win32/Tnega!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 75 62 61 72 75 20 44 69 6d 65 4d 6f 64 73 20 45 43 55 20 52 65 67 2e 70 64 62 } //1 Subaru DimeMods ECU Reg.pdb
		$a_81_1 = {53 75 62 61 72 75 20 44 69 6d 65 4d 6f 64 73 20 45 43 55 20 52 65 67 } //1 Subaru DimeMods ECU Reg
		$a_81_2 = {43 68 65 63 6b 46 6f 72 53 79 6e 63 } //1 CheckForSync
		$a_81_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_5 = {53 75 62 61 72 75 20 44 69 6d 65 4d 6f 64 73 20 45 43 55 20 52 65 67 5c 53 75 62 61 72 75 20 44 69 6d 65 4d 6f 64 73 20 45 43 55 20 52 65 67 } //1 Subaru DimeMods ECU Reg\Subaru DimeMods ECU Reg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}