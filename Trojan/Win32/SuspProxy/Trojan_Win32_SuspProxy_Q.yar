
rule Trojan_Win32_SuspProxy_Q{
	meta:
		description = "Trojan:Win32/SuspProxy.Q,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 20 55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 } //powershell.exe -c Unblock-File  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {70 73 5f 65 6d 70 69 72 65 5f 73 61 6d 70 6c 65 2e 70 73 31 } //ps_empire_sample.ps1  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}