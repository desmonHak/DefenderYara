
rule Ransom_Win32_FileCoder_GXV_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {01 d0 0f b6 c0 29 d0 89 c2 8b 45 e0 0f b6 00 31 c2 8b 45 e0 88 10 } //10
		$a_03_1 = {01 d0 0f b6 18 8b 45 ?? 83 e0 ?? 0f b6 8c 05 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? 01 d0 31 cb 89 da 88 10 83 45 e0 } //10
		$a_03_2 = {0f b6 00 89 c1 8d 95 ?? ?? ?? ?? 8b 45 ?? 01 d0 0f b6 00 31 c1 8d 95 ?? ?? ?? ?? 8b 45 e4 01 d0 88 08 83 45 e4 } //10
		$a_03_3 = {89 d1 89 ca 8b 45 ?? 89 14 24 89 c1 e8 ?? ?? ?? ?? 83 ec ?? 0f b6 00 88 45 ?? 8d 45 ?? 8b 55 ?? 89 14 24 89 c1 e8 ?? ?? ?? ?? 83 ec ?? 0f b6 10 0f b6 4d ?? 31 ca 88 10 83 45 } //10
		$a_01_4 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10+(#a_01_4  & 1)*1) >=11
 
}