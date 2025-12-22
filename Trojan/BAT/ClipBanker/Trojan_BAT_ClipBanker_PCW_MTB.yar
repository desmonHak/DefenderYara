
rule Trojan_BAT_ClipBanker_PCW_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 07 11 08 20 ff 00 00 00 5f d2 6f 2e 00 00 0a 11 0a 20 ca e8 83 06 5a 20 6f 9c c1 c0 61 38 3f fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}