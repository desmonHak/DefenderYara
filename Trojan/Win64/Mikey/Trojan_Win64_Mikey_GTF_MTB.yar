
rule Trojan_Win64_Mikey_GTF_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b c6 4c 8b ce 40 88 70 ?? 42 0f b6 54 0d ?? 42 32 54 0d ?? 4d 8d 49 01 49 63 c8 41 ff c0 88 14 01 41 83 f8 73 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}