
rule Trojan_BAT_SnakeKeylogger_EANR_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EANR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0f 1f 61 5a 61 13 10 02 11 0e 11 0f ?? ?? ?? ?? ?? 13 11 04 03 ?? ?? ?? ?? ?? 59 13 12 11 12 13 13 11 13 19 31 03 19 13 13 11 13 16 2f 03 16 13 13 11 06 16 5f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}