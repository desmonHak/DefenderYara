
rule Trojan_BAT_AgentTesla_GVF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 b8 ff ff ff 26 20 02 00 00 00 38 ad ff ff ff 02 28 0e 00 00 0a 03 6f 0f 00 00 0a 13 00 } //2
		$a_01_1 = {28 0b 00 00 06 72 e7 00 00 70 7e 04 00 00 04 6f 14 00 00 0a 74 01 00 00 1b 2a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}