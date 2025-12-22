
rule Trojan_Win32_SuspProxi_I{
	meta:
		description = "Trojan:Win32/SuspProxi.I,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 79 70 65 } //cmd.exe /c type  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_SuspProxi_I_2{
	meta:
		description = "Trojan:Win32/SuspProxi.I,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 6d 6b 64 69 72 } //cmd.exe /c mkdir  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 46 73 73 } //AppData\Local\Microsoft\EdgeFss  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}