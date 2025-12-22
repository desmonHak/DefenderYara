
rule Trojan_BAT_AgentTesla_APFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 07 28 ?? 00 00 0a 13 04 08 09 11 04 6f ?? 00 00 0a 13 05 02 73 ?? 00 00 0a 13 06 11 06 11 05 16 73 ?? 00 00 0a 13 07 73 ?? 00 00 0a 13 08 11 07 11 08 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 09 dd } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}