
rule Trojan_Win32_SuspDisco_B{
	meta:
		description = "Trojan:Win32/SuspDisco.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_1 = {2f 41 6c 6c 6f 77 55 6e 73 61 66 65 } ///AllowUnsafe  1
		$a_80_2 = {53 69 74 52 65 70 2e 65 78 65 } //SitRep.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}