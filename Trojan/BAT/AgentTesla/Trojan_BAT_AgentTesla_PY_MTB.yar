
rule Trojan_BAT_AgentTesla_PY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 45 03 00 00 00 04 00 00 00 0c 00 00 00 19 00 00 00 16 0d 2b ea 08 16 31 13 17 0d 2b e2 03 06 16 08 6f 13 00 00 0a 18 0d 2b d5 } //5
		$a_01_1 = {20 00 10 00 00 8d 1b 00 00 01 0a 02 06 16 06 8e 69 6f 88 00 00 0a 0b 07 16 30 01 2a 03 06 16 07 6f 13 00 00 0a 2b e4 } //3
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=9
 
}