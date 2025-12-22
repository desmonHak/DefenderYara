
rule Ransom_Win64_FileCoder_GP_AMTB{
	meta:
		description = "Ransom:Win64/FileCoder.GP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {50 61 79 20 6d 65 20 24 31 30 30 30 20 77 69 74 68 69 6e 20 37 32 20 68 6f 75 72 73 20 6f 72 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 20 66 6f 72 65 76 65 72 2e } //Pay me $1000 within 72 hours or your files will be deleted forever.  1
		$a_80_1 = {43 6f 6e 74 61 63 74 20 6d 65 20 61 74 20 5b 65 6d 61 69 6c 20 61 64 64 72 65 73 73 5d 2e } //Contact me at [email address].  1
		$a_80_2 = {43 3a 5c 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 65 62 4d 6f 6e 65 79 5c } //C:\\Program Files\WebMoney\  1
		$a_80_3 = {53 65 6e 64 20 75 73 20 31 30 30 30 30 30 20 62 69 74 63 6f 69 6e } //Send us 100000 bitcoin  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}