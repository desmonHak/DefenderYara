
rule Trojan_Win64_Mint_AHB_MTB{
	meta:
		description = "Trojan:Win64/Mint.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 17 48 ff c2 03 c3 69 c8 01 01 00 00 8b d9 c1 eb 06 33 d9 49 3b d0 75 } //10
		$a_01_1 = {48 8b ca 49 8b c1 83 e1 07 48 2b c1 0f b6 00 41 30 04 10 48 ff c2 48 3b d7 72 } //5
		$a_01_2 = {48 8b c1 83 e0 07 42 0f b6 04 00 30 04 0a 48 ff c1 48 3b cf 72 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}