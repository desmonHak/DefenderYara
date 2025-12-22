
rule Trojan_Win32_SusCertutil_A{
	meta:
		description = "Trojan:Win32/SusCertutil.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 64 65 63 6f 64 65 } //certutil.exe -decode  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_00_2 = {2e 00 65 00 78 00 65 00 } //1 .exe
		$a_00_3 = {2e 00 74 00 78 00 74 00 } //1 .txt
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}