
rule Trojan_BAT_Heracles_ZOK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 0b 1c 13 06 38 45 ff ff ff 02 8c 01 00 00 1b 03 04 6f ?? 00 00 0a 0b 1c 13 06 38 2f ff ff ff 06 17 58 0a 1f 3b 13 04 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}