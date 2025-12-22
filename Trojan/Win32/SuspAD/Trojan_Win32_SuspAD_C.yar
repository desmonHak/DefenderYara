
rule Trojan_Win32_SuspAD_C{
	meta:
		description = "Trojan:Win32/SuspAD.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_80_0 = {69 70 63 6f 6e 66 69 67 2e 65 78 65 20 2f 61 6c 6c } //ipconfig.exe /all  1
		$a_80_1 = {6e 65 74 2e 65 78 65 20 75 73 65 72 } //net.exe user  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}