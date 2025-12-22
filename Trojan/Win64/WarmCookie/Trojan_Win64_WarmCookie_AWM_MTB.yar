
rule Trojan_Win64_WarmCookie_AWM_MTB{
	meta:
		description = "Trojan:Win64/WarmCookie.AWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 14 01 48 8b 45 10 88 50 01 48 8b 45 10 0f b6 40 01 0f b6 c0 48 63 d0 48 8b 45 10 48 01 d0 48 8d 50 02 48 8b 45 10 0f b6 00 0f b6 c0 48 63 c8 48 8b 45 10 48 01 c8 48 83 c0 02 48 89 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}