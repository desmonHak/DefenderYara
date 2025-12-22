
rule Trojan_BAT_Taskun_ABKB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ABKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 13 20 83 00 00 00 5a 11 14 58 61 16 5f 13 29 11 } //5
		$a_03_1 = {11 09 16 28 ?? 00 00 06 02 28 ?? 00 00 06 61 02 28 ?? 00 00 06 18 62 61 13 0a } //2
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}