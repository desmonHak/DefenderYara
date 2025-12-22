
rule Ransom_Win32_Cephalus_YBH_MTB{
	meta:
		description = "Ransom:Win32/Cephalus.YBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 69 63 2e 62 6d 70 72 65 66 65 72 65 72 72 65 66 72 65 73 68 72 75 6e 6e 69 6e 67 } //1 pic.bmprefererrefreshrunning
		$a_01_1 = {52 4c 6f 63 6b 65 72 } //1 RLocker
		$a_01_2 = {3c 3d 3e 3f 40 42 43 4c 4d 4e 4f 50 53 5a } //1 <=>?@BCLMNOPSZ
		$a_01_3 = {48 33 44 68 51 7a 65 72 33 4d 61 79 68 65 70 33 38 73 79 49 73 37 31 67 59 44 51 68 } //1 H3DhQzer3Mayhep38syIs71gYDQh
		$a_01_4 = {67 6f 6c 61 6e 67 2e 6f 72 67 } //1 golang.org
		$a_01_5 = {89 84 24 90 00 00 00 c7 40 6c 64 00 00 00 c7 40 78 00 04 6b f4 c7 40 7c 14 00 00 00 c7 40 60 00 e4 0b 54 c7 40 64 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}