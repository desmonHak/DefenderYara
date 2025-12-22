
rule Trojan_Win64_Lazy_B_AMTB{
	meta:
		description = "Trojan:Win64/Lazy.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 6f 75 72 63 65 5f 73 74 65 61 6c 65 72 [0-50] 54 65 6c 65 67 72 61 6d 53 74 65 61 6c 65 72 2e 70 64 62 } //2
		$a_81_1 = {54 65 6c 65 67 72 61 6d 20 55 70 6c 6f 61 64 65 72 } //2 Telegram Uploader
		$a_81_2 = {2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 } //1 /sendDocument
		$a_81_3 = {6b 65 79 5f 64 61 74 61 73 } //1 key_datas
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=6
 
}