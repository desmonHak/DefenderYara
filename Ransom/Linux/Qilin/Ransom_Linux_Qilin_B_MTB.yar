
rule Ransom_Linux_Qilin_B_MTB{
	meta:
		description = "Ransom:Linux/Qilin.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6c 61 70 73 65 64 20 66 6f 72 20 70 61 79 6c 6f 61 64 20 65 6e 63 72 79 70 74 69 6f 6e 3a 20 25 6c 6c 75 20 6d 73 } //1 Elapsed for payload encryption: %llu ms
		$a_01_1 = {52 65 6e 61 6d 65 64 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 20 27 25 73 27 20 74 6f 20 25 73 } //1 Renamed encrypted file '%s' to %s
		$a_01_2 = {25 73 5f 52 45 43 4f 56 45 52 2e 74 78 74 } //1 %s_RECOVER.txt
		$a_01_3 = {4b 69 6c 6c 20 70 72 6f 63 65 73 73 65 73 20 64 69 73 61 62 6c 65 64 } //1 Kill processes disabled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}