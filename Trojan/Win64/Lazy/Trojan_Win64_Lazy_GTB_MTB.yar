
rule Trojan_Win64_Lazy_GTB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 08 88 45 ff 48 8b 45 00 48 89 45 b8 48 8b 4d 30 48 89 4d c0 48 39 c8 ?? ?? 48 8b 4d 00 48 8b 45 38 0f b6 55 0f 44 0f b6 45 ff 44 31 c2 44 0f b6 45 2f 44 31 c2 88 14 08 8a 45 0f 88 45 2f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}