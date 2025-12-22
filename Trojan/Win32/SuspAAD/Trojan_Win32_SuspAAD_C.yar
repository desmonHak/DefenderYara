
rule Trojan_Win32_SuspAAD_C{
	meta:
		description = "Trojan:Win32/SuspAAD.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_80_0 = {69 70 63 6f 6e 66 69 67 2e 65 78 65 20 2f 61 6c 6c } //ipconfig.exe /all  1
		$a_80_1 = {6e 65 74 2e 65 78 65 20 75 73 65 72 } //net.exe user  1
		$a_00_2 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 77 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98w0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=1
 
}
rule Trojan_Win32_SuspAAD_C_2{
	meta:
		description = "Trojan:Win32/SuspAAD.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 68 6f 61 6d 69 2e 65 78 65 } //whoami.exe  1
		$a_80_1 = {2f 61 6c 6c } ///all  1
		$a_80_2 = {2f 67 72 6f 75 70 73 } ///groups  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=2
 
}