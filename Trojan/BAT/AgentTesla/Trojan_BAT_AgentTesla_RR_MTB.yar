
rule Trojan_BAT_AgentTesla_RR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 20 00 d8 00 00 72 } //1
		$a_01_1 = {48 6f 75 72 6c 79 43 68 69 6d 65 } //1 HourlyChime
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}