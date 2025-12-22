
rule Backdoor_Win64_Stowaway_GVA_MTB{
	meta:
		description = "Backdoor:Win64/Stowaway.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 41 6c 6c 20 72 75 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 63 6c 65 61 72 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //1 [*]All rules have been cleared successfully!
		$a_01_1 = {5c 6e 5b 2a 5d 44 6f 77 6e 6c 6f 61 64 69 6e 67 20 66 69 6c 65 2c 70 6c 65 61 73 65 20 77 61 69 74 2e 2e 2e 2e 2e 2e } //1 \n[*]Downloading file,please wait......
		$a_01_2 = {5b 2a 5d 41 64 6d 69 6e 20 73 65 65 6d 73 20 73 74 69 6c 6c 20 64 6f 77 6e } //1 [*]Admin seems still down
		$a_01_3 = {53 74 6f 77 61 77 61 79 } //5 Stowaway
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5) >=7
 
}