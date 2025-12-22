
rule Ransom_Win64_WhiteLock_BA_MTB{
	meta:
		description = "Ransom:Win64/WhiteLock.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 73 79 73 74 65 6d 73 20 68 61 76 65 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 2c 20 61 6e 64 20 61 6c 6c 20 69 6d 70 6f 72 74 61 6e 74 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 68 61 73 20 62 65 65 6e 20 65 78 74 72 61 63 74 65 64 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 2e } //1 Your systems have been compromised, and all important information has been extracted and encrypted.
		$a_81_1 = {57 68 61 74 20 68 61 70 70 65 6e 73 20 69 66 20 79 6f 75 20 64 6f 6e 27 74 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d } //1 What happens if you don't pay the ransom
		$a_81_2 = {41 6c 6c 20 79 6f 75 72 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 77 69 6c 6c 20 62 65 20 73 6f 6c 64 20 61 6e 64 20 70 75 62 6c 69 73 68 65 64 20 6f 6e 20 74 68 65 20 64 61 72 6b 20 77 65 62 } //1 All your information will be sold and published on the dark web
		$a_81_3 = {54 6f 72 20 42 72 6f 77 73 65 72 } //1 Tor Browser
		$a_81_4 = {2e 6f 6e 69 6f 6e } //1 .onion
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}