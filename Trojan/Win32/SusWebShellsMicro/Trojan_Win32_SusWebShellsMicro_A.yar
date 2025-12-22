
rule Trojan_Win32_SusWebShellsMicro_A{
	meta:
		description = "Trojan:Win32/SusWebShellsMicro.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {70 6f 75 79 61 2e 61 73 70 } //pouya.asp  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}