
rule Trojan_Win64_Mikey_AD_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 74 24 10 89 f7 40 2a 7c 24 08 40 32 7c 24 04 40 f6 df 48 39 ca be 58 00 00 00 41 0f 42 f0 4a 8b 34 0e 4c 01 d6 48 89 d3 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}