
rule Trojan_Win32_SuspProxy_MK{
	meta:
		description = "Trojan:Win32/SuspProxy.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {75 72 6c 2e 64 6c 6c } //url.dll  1
		$a_80_2 = {54 65 6c 6e 65 74 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72 } //TelnetProtocolHandler  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_Win32_SuspProxy_MK_2{
	meta:
		description = "Trojan:Win32/SuspProxy.MK,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 73 63 72 69 70 74 2e 65 78 65 20 } //cscript.exe   1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {73 69 6c 65 6e 63 65 2e 76 62 73 } //silence.vbs  1
		$a_00_3 = {2e 00 65 00 78 00 65 00 } //1 .exe
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}