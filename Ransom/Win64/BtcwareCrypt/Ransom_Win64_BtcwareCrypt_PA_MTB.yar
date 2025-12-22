
rule Ransom_Win64_BtcwareCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/BtcwareCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_1 = {72 6d 64 69 72 20 2f 73 20 2f 71 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 20 32 3e 6e 75 6c } //1 rmdir /s /q C:\Windows\System32 2>nul
		$a_01_2 = {59 4f 55 52 20 53 59 53 54 45 4d 20 48 41 53 20 42 45 45 4e 20 54 41 4b 45 4e 20 4f 56 45 52 20 42 59 20 57 48 4f 2d 41 4d 2d 49 2d 34 30 34 } //3 YOUR SYSTEM HAS BEEN TAKEN OVER BY WHO-AM-I-404
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}