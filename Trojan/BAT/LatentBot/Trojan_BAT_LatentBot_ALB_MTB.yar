
rule Trojan_BAT_LatentBot_ALB_MTB{
	meta:
		description = "Trojan:BAT/LatentBot.ALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 17 59 13 08 11 08 16 31 64 0e 05 2c 1e 0e 05 8e 69 17 31 17 0e 05 8e 69 09 6f ?? 00 00 0a 18 5a 58 19 5d 2d 06 16 28 ?? 00 00 0a 06 12 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}