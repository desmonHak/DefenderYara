
rule Trojan_BAT_XWorm_AH_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 e1 2b ad de 20 56 eb 52 21 61 66 20 03 00 00 00 63 20 d9 8b 4a 12 66 20 01 00 00 00 63 20 f4 45 25 09 58 20 1b 5e e1 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}