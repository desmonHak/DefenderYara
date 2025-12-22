
rule Trojan_BAT_LokiBot_MGV_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.MGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 1f 10 2b 48 11 05 07 02 07 91 11 06 11 06 11 04 84 95 11 06 11 07 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c 1f 0c 2b 22 11 09 20 ff 00 00 00 13 0b 11 0b 3e 14 01 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}