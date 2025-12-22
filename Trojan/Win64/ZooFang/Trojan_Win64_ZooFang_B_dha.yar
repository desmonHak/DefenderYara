
rule Trojan_Win64_ZooFang_B_dha{
	meta:
		description = "Trojan:Win64/ZooFang.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 53 00 5f 00 4f 00 66 00 66 00 69 00 63 00 65 00 5f 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 5f 00 69 00 6d 00 61 00 67 00 65 00 5f 00 73 00 } //1 MS_Office_locker_image_s
		$a_01_1 = {6d 00 73 00 4f 00 66 00 66 00 69 00 63 00 65 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 5f 00 5f 00 77 00 } //1 msOfficeLocker__w
		$a_01_2 = {70 72 6e 66 6c 64 72 2e 64 6c 6c } //1 prnfldr.dll
		$a_81_3 = {31 26 3a 31 38 67 66 7a 30 38 38 54 } //1 1&:18gfz088T
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}