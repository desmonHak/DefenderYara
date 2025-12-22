
rule Trojan_Win32_SuspProxi_G{
	meta:
		description = "Trojan:Win32/SuspProxi.G,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6d 73 69 65 78 65 63 2e 65 78 65 20 2f 71 20 2f 69 } //msiexec.exe /q /i  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {69 6e 2e 73 79 73 } //in.sys  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}