
rule Trojan_BAT_Snakekeylogger_SPYT_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.SPYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 11 07 58 0e 06 1d 6a 5f 69 58 61 0a 02 09 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 13 0b 11 0b 13 0a 11 0a } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}