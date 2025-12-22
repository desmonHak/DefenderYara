
rule Trojan_Win64_CobaltStrike_GVO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 f6 66 41 89 34 1e 0f 57 c0 0f 11 45 ff f3 0f 7f 75 0f c6 45 ff 00 48 8d 5d df 4c 8b 4d df 4c 8b 5d f7 49 83 fb 07 49 0f 47 d9 48 8d 4d df 49 0f 47 c9 48 8b 45 ef 48 8d 3c 41 48 3b df 74 25 } //2
		$a_01_1 = {6b c9 21 41 03 c8 44 0f be 02 48 8d 52 01 45 85 c0 75 ed } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}