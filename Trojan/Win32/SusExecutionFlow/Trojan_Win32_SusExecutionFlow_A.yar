
rule Trojan_Win32_SusExecutionFlow_A{
	meta:
		description = "Trojan:Win32/SusExecutionFlow.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 69 72 } //cmd.exe /c dir  1
		$a_80_1 = {6d 6b 64 69 72 } //mkdir  1
		$a_80_2 = {6b 77 6f 72 6b 69 6e 67 } //kworking  1
		$a_00_3 = {2e 00 65 00 78 00 65 00 } //1 .exe
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}