
rule Trojan_BAT_Noon_ZRN_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 14 1f 3d 5a 61 13 15 02 11 13 11 14 6f ?? 00 00 0a 13 16 04 03 6f ?? 00 00 0a 59 13 17 11 17 13 18 11 18 19 31 03 19 13 18 11 18 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}