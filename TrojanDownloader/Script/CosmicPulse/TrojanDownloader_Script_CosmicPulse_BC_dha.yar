
rule TrojanDownloader_Script_CosmicPulse_BC_dha{
	meta:
		description = "TrojanDownloader:Script/CosmicPulse.BC!dha,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 00 63 00 68 00 65 00 63 00 6b 00 5c 00 [0-40] 2e 00 64 00 6c 00 6c 00 2c 00 76 00 65 00 72 00 69 00 66 00 79 00 6d 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}