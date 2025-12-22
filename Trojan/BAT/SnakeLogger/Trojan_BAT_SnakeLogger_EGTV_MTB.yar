
rule Trojan_BAT_SnakeLogger_EGTV_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.EGTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 17 59 25 0d 16 fe 02 16 fe 01 13 0a 11 0a 2c 02 2b 41 03 12 0c ?? ?? ?? ?? ?? ?? ?? 00 00 0a 09 17 59 25 0d 16 fe 02 16 fe 01 13 0b 11 0b 2c 02 2b 21 03 12 0c ?? ?? ?? ?? ?? ?? ?? 00 00 0a 06 17 58 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}