
rule Trojan_Win64_Tedy_CF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 d0 48 f7 e9 48 c1 fa 07 48 69 d2 ?? ?? ?? ?? 49 89 c9 48 29 d1 48 8d 91 ?? ?? ?? ?? 48 39 d3 0f 8d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}