
rule Trojan_Win32_MalIntExpDiagChildProc_AA{
	meta:
		description = "Trojan:Win32/MalIntExpDiagChildProc.AA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 65 00 78 00 65 00 } //1 ipconfig.exe
		$a_00_1 = {6e 00 65 00 74 00 73 00 68 00 2e 00 65 00 78 00 65 00 } //1 netsh.exe
		$a_00_2 = {72 00 6f 00 75 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 route.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}