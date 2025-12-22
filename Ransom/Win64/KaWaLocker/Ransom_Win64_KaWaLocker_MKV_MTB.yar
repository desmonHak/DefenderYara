
rule Ransom_Win64_KaWaLocker_MKV_MTB{
	meta:
		description = "Ransom:Win64/KaWaLocker.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 65 73 6b 74 6f 70 5c 64 65 6d 6f 5f 73 72 63 5f 32 2e 31 2e 37 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 65 6e 63 2e 70 64 62 } //5 Desktop\demo_src_2.1.7\x64\Release\enc.pdb
		$a_81_1 = {21 21 52 65 73 74 6f 72 65 2d 4d 79 2d 66 69 6c 65 2d 4b 61 76 76 61 2e 74 78 74 } //4 !!Restore-My-file-Kavva.txt
		$a_81_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 } //1 vssadmin.exe dele
		$a_81_3 = {74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 te shadows /all /quiet
		$a_81_4 = {73 65 6c 66 5f 64 65 6c 65 74 65 } //1 self_delete
		$a_81_5 = {61 6e 6f 6e 79 6d 6f 75 73 } //1 anonymous
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*4+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=13
 
}