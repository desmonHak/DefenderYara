
rule Trojan_BAT_DarkComet_BAA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 08 5d ?? ?? ?? ?? ?? d2 13 05 11 05 11 04 1f 17 58 08 58 1f 1f 5f 63 20 ff 00 00 00 5f ?? ?? ?? ?? ?? 13 06 06 11 04 8f 1e 00 00 01 25 71 1e 00 00 01 11 06 61 d2 81 1e 00 00 01 11 04 17 58 13 04 11 04 09 32 b7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}