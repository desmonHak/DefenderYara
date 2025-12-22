
rule Trojan_Win32_SusColdFire_A{
	meta:
		description = "Trojan:Win32/SusColdFire.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_1 = {63 6f 6c 64 66 69 72 65 2e 65 78 65 20 } //coldfire.exe   1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}