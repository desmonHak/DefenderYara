
rule Trojan_Win64_Tedy_NY_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {49 8b d6 48 03 db 48 89 06 4c 8b c3 48 89 6e ?? 48 8b c8 48 8b f8 e8 4b a6 02 00 33 c0 66 89 04 3b 48 8b 7c 24 20 } //2
		$a_03_1 = {48 03 db 4c 8b c3 48 c7 41 18 07 00 00 00 e8 9d a6 02 00 33 c0 66 89 04 33 48 83 c4 ?? 41 5e 5e 5d 5b } //1
		$a_01_2 = {44 4c 4c 20 69 6e 6a 65 63 74 65 64 } //1 DLL injected
		$a_01_3 = {63 68 72 6f 6d 65 5f 64 65 63 72 79 70 74 2e 64 6c 6c } //1 chrome_decrypt.dll
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}