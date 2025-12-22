
rule Trojan_BAT_Webshell_SPZB_MTB{
	meta:
		description = "Trojan:BAT/Webshell.SPZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 06 07 13 09 1f 0b 8d 01 00 00 01 13 0a 11 0a 16 11 09 a2 11 0a 17 72 f6 04 00 70 a2 11 0a 18 11 06 } //2
		$a_01_1 = {6f 00 73 00 76 00 6d 00 68 00 64 00 66 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 osvmhdfl.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}