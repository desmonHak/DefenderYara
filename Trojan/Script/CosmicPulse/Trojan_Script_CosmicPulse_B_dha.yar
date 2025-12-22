
rule Trojan_Script_CosmicPulse_B_dha{
	meta:
		description = "Trojan:Script/CosmicPulse.B!dha,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 [0-02] 3a 00 2f 00 2f 00 [0-40] 2f 00 76 00 69 00 65 00 77 00 2e 00 70 00 68 00 70 00 3f 00 [0-20] 26 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}