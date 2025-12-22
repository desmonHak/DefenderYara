
rule Trojan_Win64_Lazy_MKS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 69 d2 43 08 21 84 48 c1 ea 20 01 c2 c1 fa 05 89 c1 c1 f9 1f 29 ca 6b ca 3e 29 c8 89 c2 48 63 d2 48 8b 45 f0 48 01 d0 8b 55 fc 48 63 ca 48 8b 55 10 48 01 ca 0f b6 } //15
		$a_01_1 = {40 41 6d 65 6c 69 65 44 61 74 61 6c 65 61 6b 73 } //10 @AmelieDataleaks
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}