
rule Trojan_BAT_Noon_ZFJ_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 20 00 01 00 00 8d ?? 00 00 01 0a 16 0b 2b 29 07 0c 16 0d 2b 17 08 17 5f 17 2e 07 08 17 64 25 0c 2b 05 08 17 64 02 61 0c 09 17 58 0d 09 1e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}