
rule Trojan_BAT_Heracles_PCW_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 08 74 07 00 00 1b 17 7e 0e 00 00 04 a2 08 74 07 00 00 1b 18 1f 17 20 ef 77 38 35 17 28 fd 00 00 06 a2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}