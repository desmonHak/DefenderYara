
rule Trojan_Win32_SuspDisco_A{
	meta:
		description = "Trojan:Win32/SuspDisco.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_1 = {52 65 63 6f 6e 65 72 61 74 6f 72 2e 65 78 65 } //Reconerator.exe  1
		$a_80_2 = {64 61 7a 7a 6c 65 55 50 2e 65 78 65 } //dazzleUP.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=2
 
}