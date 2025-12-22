
rule HackTool_Linux_Kscan_A_MTB{
	meta:
		description = "HackTool:Linux/Kscan.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 68 79 64 72 61 2f 72 65 64 69 73 2e 72 65 61 64 52 65 73 70 6f 6e 73 65 } //1 kscan/core/hydra/redis.readResponse
		$a_01_1 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 73 63 61 6e 6e 65 72 2e 4e 65 77 55 52 4c 53 63 61 6e 6e 65 72 } //1 kscan/core/scanner.NewURLScanner
		$a_01_2 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 73 63 61 6e 6e 65 72 2e 4e 65 77 48 79 64 72 61 53 63 61 6e 6e 65 72 } //1 kscan/core/scanner.NewHydraScanner
		$a_01_3 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 73 63 61 6e 6e 65 72 2e 28 2a 49 50 43 6c 69 65 6e 74 29 2e 50 75 73 68 } //1 kscan/core/scanner.(*IPClient).Push
		$a_01_4 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 68 79 64 72 61 2e 28 2a 43 72 61 63 6b 65 72 29 2e 73 75 63 63 65 73 73 } //1 kscan/core/hydra.(*Cracker).success
		$a_01_5 = {6b 73 63 61 6e 2f 63 6f 72 65 2f 73 70 79 2e 48 6f 73 74 44 69 73 63 6f 76 65 72 79 49 63 6d 70 50 6f 6f 6c } //1 kscan/core/spy.HostDiscoveryIcmpPool
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}