
rule Trojan_BAT_AgentTesla_CED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {0b 07 16 73 ?? ?? ?? 0a 0c 20 00 00 10 00 8d ?? ?? ?? 01 0d 38 ?? ?? ?? ?? 06 09 16 11 04 6f ?? ?? ?? 0a 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 3d ?? ?? ?? ?? 06 6f } //1
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}