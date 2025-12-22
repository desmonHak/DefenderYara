
rule Trojan_Win32_SusRegCredsHKLM_MK{
	meta:
		description = "Trojan:Win32/SusRegCredsHKLM.MK,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {72 65 67 2e 65 78 65 20 71 75 65 72 79 20 48 4b 4c 4d 20 2f 66 20 70 61 73 73 77 6f 72 64 } //reg.exe query HKLM /f password  1
		$a_80_4 = {2f 74 20 52 45 47 5f 53 5a 20 2f 73 20 } ///t REG_SZ /s   1
		$a_00_5 = {38 00 32 00 33 00 38 00 35 00 33 00 64 00 37 00 2d 00 31 00 31 00 34 00 61 00 2d 00 34 00 37 00 34 00 34 00 2d 00 62 00 32 00 36 00 35 00 2d 00 34 00 64 00 30 00 66 00 63 00 35 00 61 00 31 00 31 00 63 00 33 00 30 00 } //-1 823853d7-114a-4744-b265-4d0fc5a11c30
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*-1) >=5
 
}
rule Trojan_Win32_SusRegCredsHKLM_MK_2{
	meta:
		description = "Trojan:Win32/SusRegCredsHKLM.MK,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {26 20 65 78 69 74 } //& exit  1
		$a_80_3 = {72 65 67 2e 65 78 65 20 71 75 65 72 79 20 48 4b 4c 4d 20 2f 66 20 70 61 73 73 77 6f 72 64 } //reg.exe query HKLM /f password  1
		$a_80_4 = {2f 74 20 52 45 47 5f 53 5a 20 2f 73 20 } ///t REG_SZ /s   1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}