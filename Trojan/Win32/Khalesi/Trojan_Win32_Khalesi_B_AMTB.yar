
rule Trojan_Win32_Khalesi_B_AMTB{
	meta:
		description = "Trojan:Win32/Khalesi.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 63 75 74 69 74 2e 6f 72 67 } //https://cutit.org  2
		$a_80_1 = {68 74 74 70 3a 2f 2f 63 6c 69 2e 72 65 } //http://cli.re  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}