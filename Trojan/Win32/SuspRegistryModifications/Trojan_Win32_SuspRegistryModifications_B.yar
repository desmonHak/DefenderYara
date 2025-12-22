
rule Trojan_Win32_SuspRegistryModifications_B{
	meta:
		description = "Trojan:Win32/SuspRegistryModifications.B,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost  1
		$a_80_2 = {2f 76 20 22 53 74 6f 72 53 79 6e 63 53 76 63 22 } ///v "StorSyncSvc"  1
		$a_80_3 = {2f 64 20 22 53 74 6f 72 53 79 6e 63 53 76 63 22 20 2f 66 } ///d "StorSyncSvc" /f  1
		$a_80_4 = {2f 74 20 52 45 47 5f 4d 55 4c 54 49 5f 53 5a } ///t REG_MULTI_SZ  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}