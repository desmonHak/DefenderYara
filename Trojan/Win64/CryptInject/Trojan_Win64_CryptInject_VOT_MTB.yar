
rule Trojan_Win64_CryptInject_VOT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.VOT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c1 66 89 84 24 48 0b 00 00 48 8b 84 24 ?? 73 00 00 48 8b 8c 24 ?? 73 00 00 48 23 c8 48 8b c1 48 8b 8c 24 ?? 73 00 00 48 89 01 48 8b 84 24 ?? 73 00 00 48 8b 8c 24 ?? 73 00 00 48 8b 00 48 03 c1 48 8b 8c 24 ?? 73 00 00 48 89 01 0f b6 44 24 50 0f b6 4c 24 52 2b c1 88 05 d7 1f 15 00 8b 84 24 f4 3e 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}