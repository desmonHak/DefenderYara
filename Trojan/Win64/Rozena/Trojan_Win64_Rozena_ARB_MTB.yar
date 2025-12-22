
rule Trojan_Win64_Rozena_ARB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.ARB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 0f b6 10 0f b6 05 ?? ?? ?? ?? 31 c2 48 8d 0d ?? ?? ?? ?? 48 8b 45 f8 48 01 c8 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}