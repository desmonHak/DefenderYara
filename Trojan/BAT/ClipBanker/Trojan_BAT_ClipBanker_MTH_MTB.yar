
rule Trojan_BAT_ClipBanker_MTH_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 08 00 00 0a 0a 06 8e 69 8d 1f 00 00 01 0b 16 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}