
rule Ransom_Win64_WannaCrypt_PAGV_MTB{
	meta:
		description = "Ransom:Win64/WannaCrypt.PAGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c9 c1 e1 09 f7 d1 44 0f af c1 41 8b c9 d1 e9 f7 d1 41 8b d0 c1 ea 0b 0b ca 41 33 c8 45 0f b6 42 ff 45 84 c0 75 } //2
		$a_01_1 = {8b ca c1 e9 0b 33 ca 69 c9 01 80 00 00 3b ce 74 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}