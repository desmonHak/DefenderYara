
rule Trojan_Win32_SusNativeAPI_A{
	meta:
		description = "Trojan:Win32/SusNativeAPI.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {63 73 70 69 70 65 } //cspipe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}