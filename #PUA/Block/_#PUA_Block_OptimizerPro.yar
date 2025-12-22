
rule _#PUA_Block_OptimizerPro{
	meta:
		description = "!#PUA:Block:OptimizerPro,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {74 6f 74 61 6c 70 63 63 61 72 65 2e 63 6f 6d 2f 6c 69 76 65 2d 63 68 61 74 } //totalpccare.com/live-chat  2
		$a_80_1 = {61 76 71 74 6f 6f 6c 73 2e 63 6f 6d } //avqtools.com  1
		$a_80_2 = {55 73 61 67 65 53 74 61 74 2e 69 6e 69 } //UsageStat.ini  1
		$a_80_3 = {52 65 63 65 69 76 65 4c 69 6e 6b 53 70 65 65 64 } //ReceiveLinkSpeed  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}