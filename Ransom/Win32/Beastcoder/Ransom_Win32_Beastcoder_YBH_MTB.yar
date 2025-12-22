
rule Ransom_Win32_Beastcoder_YBH_MTB{
	meta:
		description = "Ransom:Win32/Beastcoder.YBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 6a 17 8d 71 04 5b 8a 16 8b 01 32 c2 88 06 46 83 eb 01 } //1
		$a_01_1 = {33 c0 80 2c 08 08 40 83 f8 17 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}