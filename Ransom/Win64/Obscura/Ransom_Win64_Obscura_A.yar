
rule Ransom_Win64_Obscura_A{
	meta:
		description = "Ransom:Win64/Obscura.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 61 69 6c 65 64 20 74 6f 20 64 65 63 6f 64 65 20 6e 6f 74 65 3a 20 25 73 } //1 failed to decode note: %s
		$a_01_1 = {70 65 65 72 20 70 75 62 6c 69 63 20 6b 65 79 20 77 72 6f 6e 67 20 73 69 7a 65 } //1 peer public key wrong size
		$a_01_2 = {5b 2b 5d 20 64 65 74 65 63 74 20 73 74 61 6e 64 61 6c 6f 6e 65 20 70 63 2e } //1 [+] detect standalone pc.
		$a_01_3 = {5b 21 21 21 5d 20 75 73 65 72 20 6e 6f 74 20 61 64 6d 69 6e 2e 20 65 78 69 74 20 5b 21 21 21 5d } //1 [!!!] user not admin. exit [!!!]
		$a_01_4 = {52 45 41 44 4d 45 2d 4f 42 53 43 55 52 41 2e 74 78 74 } //1 README-OBSCURA.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}