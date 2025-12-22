
rule Trojan_BAT_SnakeKeylogger_AQDB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AQDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {0e 04 06 1f 11 91 18 62 61 10 04 } //5
		$a_01_1 = {06 11 0d 11 0e 58 0e 04 58 20 ff 00 00 00 5f 91 13 0f } //2
		$a_01_2 = {07 06 11 08 91 58 11 09 20 ff 00 00 00 5f 58 20 ff 00 00 00 5f 0b 06 11 08 91 13 0a 06 11 08 06 07 91 9c } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}