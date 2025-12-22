
rule Trojan_Win32_SuspAD_D{
	meta:
		description = "Trojan:Win32/SuspAD.D,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {71 62 6f 74 44 69 73 63 6f 76 65 72 79 2e 62 61 74 } //qbotDiscovery.bat  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}