
rule Trojan_Win64_BanditStealer_ABT_MTB{
	meta:
		description = "Trojan:Win64/BanditStealer.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 f2 88 54 24 42 0f b6 54 24 21 0f b6 74 24 2f 31 f2 88 54 24 43 0f b6 54 24 2c 0f b6 74 24 1b 29 f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}