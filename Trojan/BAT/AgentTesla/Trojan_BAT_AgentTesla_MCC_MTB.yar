
rule Trojan_BAT_AgentTesla_MCC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {37 00 37 00 35 00 30 00 36 00 34 00 35 00 35 } //2
		$a_01_1 = {53 6c 61 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 Slack.Properties.Resources.resource
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 } //1 System.Activator
		$a_01_3 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}