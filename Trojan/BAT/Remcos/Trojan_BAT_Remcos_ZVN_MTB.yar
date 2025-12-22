
rule Trojan_BAT_Remcos_ZVN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 09 0b 04 03 07 5d 9a 28 ?? 00 00 0a 02 28 ?? 01 00 06 0a 2b 00 06 2a } //6
		$a_01_1 = {02 03 60 02 66 03 66 60 5f 0a 2b 00 06 2a } //4
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}