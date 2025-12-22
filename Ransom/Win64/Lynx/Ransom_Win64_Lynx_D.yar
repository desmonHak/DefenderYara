
rule Ransom_Win64_Lynx_D{
	meta:
		description = "Ransom:Win64/Lynx.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 00 2a 00 5d 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 66 00 69 00 6c 00 65 00 3a 00 20 00 25 00 73 00 } //1 [*] Encrypting file: %s
		$a_01_1 = {5b 00 2a 00 5d 00 20 00 4c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 64 00 72 00 69 00 76 00 65 00 73 00 2e 00 2e 00 2e 00 } //1 [*] Loading hidden drives...
		$a_01_2 = {5b 2a 5d 20 4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 65 73 2e 2e 2e } //1 [*] Killing processes...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}