
rule HackTool_MacOS_Kscan_A_MTB{
	meta:
		description = "HackTool:MacOS/Kscan.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 68 79 64 72 61 2f 72 65 64 69 73 2e 72 65 61 64 52 65 73 70 6f 6e 73 65 } //1 kscan/core/hydra/redis.readResponse
		$a_01_1 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 68 79 64 72 61 2e 72 64 70 43 72 61 63 6b 65 72 } //1 kscan/core/hydra.rdpCracker
		$a_01_2 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 68 79 64 72 61 2f 73 73 68 2e 43 68 65 63 6b } //1 kscan/core/hydra/ssh.Check
		$a_01_3 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 73 70 79 2e 64 6e 73 54 65 73 74 69 6e 67 } //1 kscan/core/spy.dnsTesting
		$a_01_4 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 73 70 79 2e 48 6f 73 74 44 69 73 63 6f 76 65 72 79 49 63 6d 70 50 6f 6f 6c } //1 kscan/core/spy.HostDiscoveryIcmpPool
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}