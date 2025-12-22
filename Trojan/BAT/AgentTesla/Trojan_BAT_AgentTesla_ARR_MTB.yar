
rule Trojan_BAT_AgentTesla_ARR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 1f 19 62 2b 1e 1d 5f 60 16 2d f6 2b 19 1d 2c ef 1e 2c ec 2b 14 2b 15 16 2c 15 26 26 } //20
		$a_01_1 = {11 07 a2 09 1a 2c 0d 17 25 2c 0a 25 2c 07 58 1a 2c 9f } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_BAT_AgentTesla_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 04 07 14 ?? ?? ?? ?? ?? 18 ?? ?? ?? ?? ?? 25 16 09 ?? ?? ?? ?? ?? a2 25 17 11 04 ?? ?? ?? ?? ?? a2 25 13 07 14 14 18 ?? ?? ?? ?? ?? 25 16 17 9c 25 17 17 9c 25 13 08 ?? ?? ?? ?? ?? 13 09 11 08 16 91 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_81_0 = {32 39 34 35 38 35 30 31 2d 39 31 63 37 2d 34 65 65 37 2d 38 38 64 66 2d 35 34 34 37 39 32 31 33 38 39 36 33 } //15 29458501-91c7-4ee7-88df-544792138963
		$a_01_1 = {6d 5f 35 65 31 65 39 31 65 64 66 63 37 32 34 34 65 37 39 37 33 62 35 62 30 30 64 32 30 38 62 37 39 62 } //10 m_5e1e91edfc7244e7973b5b00d208b79b
		$a_81_2 = {3c 4d 6f 64 75 6c 65 3e 7b 64 66 65 37 66 36 30 33 2d 66 36 61 63 2d 34 39 38 64 2d 39 37 33 63 2d 66 30 35 38 32 39 63 66 32 61 33 33 7d } //5 <Module>{dfe7f603-f6ac-498d-973c-f05829cf2a33}
	condition:
		((#a_81_0  & 1)*15+(#a_01_1  & 1)*10+(#a_81_2  & 1)*5) >=30
 
}