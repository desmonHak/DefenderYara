
rule Trojan_BAT_Lazy_NB_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 07 1f 10 8d ?? 00 00 01 0c 08 16 1d 9c 08 17 1c 9c 08 18 1b 9c 08 19 1a 9c 08 } //2
		$a_01_1 = {53 6b 75 70 2e 52 65 73 6f 75 72 63 65 73 } //1 Skup.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}