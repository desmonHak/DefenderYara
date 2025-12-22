
rule Trojan_BAT_ShadowLoader_B_dha{
	meta:
		description = "Trojan:BAT/ShadowLoader.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {02 58 25 1e 64 61 7e 90 01 01 00 00 04 58 25 1e 62 61 7e 90 01 01 00 00 04 5a 25 1e 64 61 2a 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}