
rule Trojan_Win64_Lazy_AU_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 39 eb b9 00 00 00 00 48 83 d1 07 31 c0 45 31 d2 49 b8 ?? ?? ?? ?? ?? ?? ?? ?? 4d 39 c3 0f 92 c0 41 0f 94 c2 49 39 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}