
rule Trojan_Win64_Cerbu_AHC_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,41 00 41 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 54 45 41 4c 45 52 20 53 54 41 52 54 45 44 } //5 STEALER STARTED
		$a_01_1 = {48 6f 73 74 69 6c 65 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 64 65 74 65 63 74 65 64 20 2d 20 65 78 69 74 69 6e 67 20 73 69 6c 65 6e 74 6c 79 } //10 Hostile environment detected - exiting silently
		$a_01_2 = {41 6c 6c 20 65 78 74 72 61 63 74 69 6f 6e 20 74 61 73 6b 73 20 66 69 6e 69 73 68 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //20 All extraction tasks finished successfully
		$a_01_3 = {43 72 65 64 69 74 20 43 61 72 64 73 20 28 61 6c 6c 20 70 72 6f 66 69 6c 65 73 29 3a } //30 Credit Cards (all profiles):
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20+(#a_01_3  & 1)*30) >=65
 
}