
rule Trojan_BAT_AsyncRAT_GDX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 4c 71 46 4e 64 51 6e 68 4c 69 5a 53 71 69 54 67 } //1 gLqFNdQnhLiZSqiTg
		$a_80_1 = {66 41 52 61 44 6b 78 45 5a 5a 6f 48 72 53 76 } //fARaDkxEZZoHrSv  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}