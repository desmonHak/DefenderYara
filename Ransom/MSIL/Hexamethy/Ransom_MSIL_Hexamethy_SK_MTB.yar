
rule Ransom_MSIL_Hexamethy_SK_MTB{
	meta:
		description = "Ransom:MSIL/Hexamethy.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 69 6e 20 68 6f 73 74 61 67 65 20 62 79 20 74 68 65 20 48 45 58 41 4d 45 54 48 59 4c 43 59 43 4c 4f 54 52 49 53 49 4c 4f 58 41 4e 45 20 52 61 6e 73 6f 6d 77 61 72 65 21 } //1 Your files are in hostage by the HEXAMETHYLCYCLOTRISILOXANE Ransomware!
		$a_81_1 = {52 41 50 49 44 4f 56 45 52 57 52 49 54 45 52 2e 65 78 65 } //1 RAPIDOVERWRITER.exe
		$a_81_2 = {2e 48 58 41 4d 54 48 59 } //1 .HXAMTHY
		$a_81_3 = {48 65 78 61 6d 65 74 68 79 5f 64 65 63 72 79 70 74 6f 72 } //1 Hexamethy_decryptor
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}