
rule Trojan_Win64_CobaltStrike_RR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 84 24 80 00 00 00 7c c6 84 24 81 00 00 00 72 c6 84 24 82 00 00 00 65 c6 84 24 83 00 00 00 79 c6 84 24 84 00 00 00 72 c6 84 24 85 00 00 00 7b c6 84 24 86 00 00 00 24 c6 84 24 87 00 00 00 25 c6 84 24 88 00 00 00 39 c6 84 24 89 00 00 00 73 c6 84 24 8a 00 00 00 7b c6 84 24 8b 00 00 00 7b c6 84 24 8c 00 00 00 17 } //1
		$a_01_1 = {44 6c 6c 53 61 66 65 43 68 65 63 6b 36 34 } //1 DllSafeCheck64
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}