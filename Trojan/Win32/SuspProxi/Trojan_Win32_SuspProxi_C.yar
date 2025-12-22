
rule Trojan_Win32_SuspProxi_C{
	meta:
		description = "Trojan:Win32/SuspProxi.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 6d 6b 64 69 72 } //cmd.exe /c mkdir  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 6c 62 5c 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 } //AppData\Local\Temp\lb\Windows Media Player  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}