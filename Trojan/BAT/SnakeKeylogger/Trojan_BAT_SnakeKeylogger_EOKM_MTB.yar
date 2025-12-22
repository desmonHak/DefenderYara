
rule Trojan_BAT_SnakeKeylogger_EOKM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EOKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 11 16 1f 3d 5a 61 13 17 00 02 11 15 11 16 ?? ?? ?? ?? ?? 13 18 04 03 ?? ?? ?? ?? ?? 59 13 19 11 19 13 1a 11 1a 19 fe 02 13 20 11 20 2c 03 19 13 1a 11 1a 16 fe 04 13 21 11 21 2c 03 16 13 1a 11 09 16 5f 13 1b 11 1b 19 5d 13 1c 17 11 1b 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}