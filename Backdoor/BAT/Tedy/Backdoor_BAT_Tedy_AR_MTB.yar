
rule Backdoor_BAT_Tedy_AR_MTB{
	meta:
		description = "Backdoor:BAT/Tedy.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 02 08 06 28 [0-10] 09 8e 69 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? ?? 13 04 09 16 11 04 } //15
		$a_03_1 = {0b 00 07 03 16 03 8e 69 6f ?? ?? ?? ?? 0c de 20 07 } //5
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}