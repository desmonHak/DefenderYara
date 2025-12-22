
rule Ransom_Linux_Trigona_E_MTB{
	meta:
		description = "Ransom:Linux/Trigona.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 6f 77 5f 74 6f 5f 64 65 63 72 79 70 74 2e 74 78 74 } //1 how_to_decrypt.txt
		$a_01_1 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 } //1 vim-cmd vmsvc/getallvms
		$a_01_2 = {2f 77 69 70 65 70 61 74 68 } //1 /wipepath
		$a_01_3 = {2e 2d 65 6e 63 72 79 70 74 65 64 } //1 .-encrypted
		$a_01_4 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 70 6f 77 65 72 2e 6f 66 66 } //1 vim-cmd vmsvc/power.off
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}