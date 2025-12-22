
rule Ransom_Win64_OslockCrypt_PC_MTB{
	meta:
		description = "Ransom:Win64/OslockCrypt.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 64 65 6c 65 74 65 73 68 61 64 6f 77 73 2f 61 6c 6c 2f 71 75 69 65 74 } //1 vssadmindeleteshadows/all/quiet
		$a_01_1 = {4b 43 56 59 20 4f 53 4c 4f 43 4b 20 56 33 2e 30 20 2d 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //2 KCVY OSLOCK V3.0 - YOUR FILES HAVE BEEN ENCRYPTED
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}