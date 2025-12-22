
rule Trojan_Win64_Lazy_BR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 e8 c1 83 04 00 8d 90 b5 9a 37 b9 03 cf 7b 86 a0 7c c8 44 d2 9e 56 59 de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}