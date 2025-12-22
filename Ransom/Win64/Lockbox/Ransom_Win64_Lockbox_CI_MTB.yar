
rule Ransom_Win64_Lockbox_CI_MTB{
	meta:
		description = "Ransom:Win64/Lockbox.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 65 6e 63 72 79 70 74 20 6e 6f 6e 63 65 } //2 Failed to encrypt nonce
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 65 6e 63 72 79 70 74 20 6b 65 79 } //2 Failed to encrypt key
		$a_01_2 = {5b 2b 5d 20 45 6e 63 72 79 70 74 69 6e 67 20 66 69 6c 65 3a } //2 [+] Encrypting file:
		$a_01_3 = {41 4e 54 49 5f 41 4e 41 4c 59 53 49 53 } //2 ANTI_ANALYSIS
		$a_01_4 = {43 4f 4d 50 55 54 45 52 4e 41 4d 45 } //2 COMPUTERNAME
		$a_01_5 = {6e 6f 74 68 69 6e 67 20 74 6f 20 65 6e 63 72 79 70 74 } //2 nothing to encrypt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}