
rule Trojan_BAT_Noon_ZRK_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b 13 05 2b 8d 02 8c 0c 00 00 1b 03 04 6f ?? 00 00 0a 0b 1b 13 05 38 ?? ff ff ff 06 17 58 0a 05 25 5a 0d 05 09 58 0d 1e 13 05 38 ?? ff ff ff 09 18 5d 2d 0f 11 06 20 82 00 00 00 91 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}