
rule Ransom_Win64_Encoder_GP_AMTB{
	meta:
		description = "Ransom:Win64/Encoder.GP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {5c 49 4d 50 4f 52 54 41 4e 54 5f 52 45 41 44 4d 45 2e 74 78 74 } //\IMPORTANT_README.txt  1
		$a_80_1 = {5c 52 45 41 44 5f 46 49 52 53 54 2e 74 78 74 } //\READ_FIRST.txt  1
		$a_80_2 = {72 65 63 6f 76 65 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //recover@protonmail.com  1
		$a_80_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 63 6c 65 61 6e 75 70 2e 62 61 74 } //C:\Windows\Temp\cleanup.bat  1
		$a_80_4 = {20 30 2e 31 20 42 54 43 20 } // 0.1 BTC   1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}