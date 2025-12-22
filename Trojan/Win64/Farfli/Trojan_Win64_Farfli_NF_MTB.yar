
rule Trojan_Win64_Farfli_NF_MTB{
	meta:
		description = "Trojan:Win64/Farfli.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c1 41 ff c9 85 c0 74 10 42 0f b6 04 02 49 ff c0 41 88 40 ff 84 c0 75 e6 48 8b c1 41 c6 00 } //2
		$a_01_1 = {48 8b d8 33 c0 48 8b fb f2 ae 48 f7 d1 48 ff c9 48 83 f9 01 76 6f } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}