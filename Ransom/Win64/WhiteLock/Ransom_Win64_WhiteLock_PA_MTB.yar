
rule Ransom_Win64_WhiteLock_PA_MTB{
	meta:
		description = "Ransom:Win64/WhiteLock.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 66 00 62 00 69 00 6e 00 } //1 .fbin
		$a_01_1 = {63 00 30 00 6e 00 74 00 61 00 63 00 74 00 2e 00 74 00 78 00 74 00 } //1 c0ntact.txt
		$a_01_2 = {61 6c 6c 20 69 6d 70 6f 72 74 61 6e 74 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 68 61 73 20 62 65 65 6e 20 65 78 74 72 61 63 74 65 64 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 2e } //2 all important information has been extracted and encrypted.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}