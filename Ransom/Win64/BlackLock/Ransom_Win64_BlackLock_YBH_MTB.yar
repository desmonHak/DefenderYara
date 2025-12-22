
rule Ransom_Win64_BlackLock_YBH_MTB{
	meta:
		description = "Ransom:Win64/BlackLock.YBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 73 74 6f 6c 65 6e } //1 files have been stolen
		$a_01_1 = {42 6c 61 63 6b 20 4c 6f 63 6b 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Black Lock Ransomware
		$a_01_2 = {64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 78 70 6f 72 74 65 64 } //1 data has been exported
		$a_01_3 = {72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 } //1 recover your files
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 20 66 6f 72 65 76 65 72 } //1 encrypted forever
		$a_01_5 = {64 61 72 6b 20 77 65 62 20 6c 6f 67 } //1 dark web log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}