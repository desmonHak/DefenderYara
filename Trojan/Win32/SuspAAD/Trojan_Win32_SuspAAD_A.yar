
rule Trojan_Win32_SuspAAD_A{
	meta:
		description = "Trojan:Win32/SuspAAD.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_80_0 = {6e 6c 74 65 73 74 2e 65 78 65 20 2f 64 63 6c 69 73 74 3a } //nltest.exe /dclist:  1
		$a_80_1 = {6e 6c 74 65 73 74 2e 65 78 65 20 2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 20 2f 61 6c 6c 5f 74 72 75 73 74 73 } //nltest.exe /domain_trusts /all_trusts  1
		$a_80_2 = {6e 65 74 2e 65 78 65 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 } //net.exe localgroup administrators  1
		$a_80_3 = {77 68 6f 61 6d 69 20 2f 67 72 6f 75 70 73 } //whoami /groups  1
		$a_00_4 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 75 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98u0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*-1) >=1
 
}
rule Trojan_Win32_SuspAAD_A_2{
	meta:
		description = "Trojan:Win32/SuspAAD.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_1 = {53 68 61 72 70 41 77 61 72 65 6e 65 73 73 2e 65 78 65 } //SharpAwareness.exe  1
		$a_80_2 = {53 68 61 72 70 41 44 55 73 65 72 49 50 2e 65 78 65 } //SharpADUserIP.exe  1
		$a_80_3 = {53 68 61 72 70 57 6e 66 44 75 6d 70 2e 65 78 65 20 2d 64 20 2d 72 } //SharpWnfDump.exe -d -r  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}