
rule Trojan_Win32_SuspAAD_B{
	meta:
		description = "Trojan:Win32/SuspAAD.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {47 65 74 2d 57 4d 49 4f 62 6a 65 63 74 20 57 69 6e 33 32 5f 4e 54 44 6f 6d 61 69 6e } //Get-WMIObject Win32_NTDomain  1
		$a_80_2 = {66 69 6e 64 73 74 72 20 44 6f 6d 61 69 6e 43 6f 6e 74 72 6f 6c 6c 65 72 } //findstr DomainController  1
		$a_00_3 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 76 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98v0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}
rule Trojan_Win32_SuspAAD_B_2{
	meta:
		description = "Trojan:Win32/SuspAAD.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {6e 6c 74 65 73 74 20 } //nltest   1
		$a_80_1 = {2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 } ///domain_trusts  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}