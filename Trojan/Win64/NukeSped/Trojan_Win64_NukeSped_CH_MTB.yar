
rule Trojan_Win64_NukeSped_CH_MTB{
	meta:
		description = "Trojan:Win64/NukeSped.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 29 ?? ?? ?? ?? ff c2 32 04 19 88 04 39 8b ca 48 3b ce 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}