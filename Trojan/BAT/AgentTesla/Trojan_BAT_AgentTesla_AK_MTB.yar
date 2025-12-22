
rule Trojan_BAT_AgentTesla_AK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 45 0b 00 00 95 5a 7e 0d 00 00 04 20 f0 0d 00 00 95 58 61 81 07 00 00 01 28 0a 00 00 06 7e 1a 00 00 04 18 9a 1f 40 95 7e 0d 00 00 04 20 94 0c 00 00 95 33 37 } //2
		$a_01_1 = {17 59 7e 0d 00 00 04 20 cf 03 00 00 95 5f 7e 0d 00 00 04 20 00 09 00 00 95 61 61 81 07 00 00 01 38 9a 00 00 00 7e 1a 00 00 04 18 9a 1f 40 95 7e 0d 00 00 04 20 c5 07 00 00 95 33 5b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}