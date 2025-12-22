
rule Trojan_BAT_Lokibot_ALY_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 11 58 16 5f 13 1d 11 1d 19 5d 13 1e 17 11 1d 58 19 5d 13 1f 18 11 1d 58 19 5d 13 20 19 8d ?? 00 00 01 13 21 11 21 16 12 1a 28 ?? 00 00 0a 9c 11 21 17 12 1a 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}