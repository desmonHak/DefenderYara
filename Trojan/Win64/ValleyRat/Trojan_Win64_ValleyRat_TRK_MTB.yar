
rule Trojan_Win64_ValleyRat_TRK_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.TRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 72 75 6e 53 65 72 76 69 63 65 } //1 main.runService
		$a_81_1 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 53 68 65 6c 6c 63 6f 64 65 } //1 main.decryptShellcode
		$a_81_2 = {6d 61 69 6e 2e 69 6e 73 74 61 6c 6c 53 65 6c 66 } //1 main.installSelf
		$a_81_3 = {6d 61 69 6e 2e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 } //1 main.loadAndExecute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}