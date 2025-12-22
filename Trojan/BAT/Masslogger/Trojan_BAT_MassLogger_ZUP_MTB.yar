
rule Trojan_BAT_MassLogger_ZUP_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 91 13 0c 02 11 0a 11 0b 6f ?? 00 00 0a 13 0d 04 03 6f ?? 00 00 0a 59 13 0e 11 0e 13 0f 11 0f 19 31 03 19 13 0f 11 0f 16 } //6
		$a_03_1 = {16 13 0f 11 0f 16 31 0d 03 12 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 11 0f 17 31 0d 03 12 0d } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}