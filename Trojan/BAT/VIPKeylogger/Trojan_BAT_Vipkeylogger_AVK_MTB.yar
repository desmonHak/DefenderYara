
rule Trojan_BAT_Vipkeylogger_AVK_MTB{
	meta:
		description = "Trojan:BAT/Vipkeylogger.AVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 91 58 11 09 20 ff 00 00 00 5f 58 20 ff 00 00 00 5f 0b 11 1c 20 ?? 01 00 00 91 1f 7f 59 13 1a } //2
		$a_01_1 = {11 0d 11 0e 58 0e 04 58 20 ff 00 00 00 5f 91 13 0f 11 1c 1f 21 91 1f 09 5b 13 1a } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Vipkeylogger_AVK_MTB_2{
	meta:
		description = "Trojan:BAT/Vipkeylogger.AVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 40 2b 44 00 11 3e 11 40 19 5f 91 13 41 11 41 16 60 11 41 fe 01 13 42 11 42 13 43 11 43 2c 21 00 03 11 41 6f ?? 00 00 0a 00 11 1e 11 3f 5a 11 40 58 13 44 11 07 11 44 11 41 6f ?? 00 00 0a 00 00 00 11 40 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}