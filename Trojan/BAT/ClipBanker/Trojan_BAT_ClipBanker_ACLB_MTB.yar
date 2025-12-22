
rule Trojan_BAT_ClipBanker_ACLB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 1b 07 08 06 08 91 7e 33 00 00 04 08 7e 33 00 00 04 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}