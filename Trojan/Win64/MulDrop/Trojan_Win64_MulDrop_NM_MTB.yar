
rule Trojan_Win64_MulDrop_NM_MTB{
	meta:
		description = "Trojan:Win64/MulDrop.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8d 05 f7 da 09 00 48 89 04 24 e8 4e f0 01 00 45 0f 57 ff 4c 8b 35 f3 1e 1a 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 08 48 8b 40 30 ff 88 3c 02 00 00 } //2
		$a_01_1 = {4c 89 74 24 08 49 8b 46 30 83 b8 3c 02 00 00 00 66 90 75 22 48 8d 05 f7 da 09 00 48 89 04 24 } //1
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_3 = {76 69 63 74 69 6d } //1 victim
		$a_01_4 = {6b 69 6c 6c } //1 kill
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}