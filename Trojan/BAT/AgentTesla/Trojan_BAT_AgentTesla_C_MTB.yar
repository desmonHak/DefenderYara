
rule Trojan_BAT_AgentTesla_C_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 11 0d 11 0e 58 0e 04 58 20 ff 00 00 00 5f 91 13 0f } //2
		$a_01_1 = {0e 04 06 1f 11 91 18 62 61 10 04 11 19 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}
rule Trojan_BAT_AgentTesla_C_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.C!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 66 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 5f 00 43 00 61 00 6c 00 63 00 75 00 6c 00 61 00 74 00 6f 00 72 00 } //1 Inflation_Calculator
		$a_01_1 = {4e 65 74 77 6f 72 6b 20 41 64 61 70 74 65 72 73 2e 64 6c 6c } //1 Network Adapters.dll
		$a_01_2 = {5c 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 46 69 6c 65 73 5c 6f 62 6a 5c 44 65 62 75 67 5c 4e 65 74 77 6f 72 6b 20 41 64 61 70 74 65 72 73 2e 70 64 62 } //1 \ConfigurationFiles\obj\Debug\Network Adapters.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}