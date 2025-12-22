
rule Trojan_Win32_RedCap_AR_MTB{
	meta:
		description = "Trojan:Win32/RedCap.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 52 33 49 4c 36 59 4a 54 4b 57 53 58 42 33 49 36 4b 52 54 41 41 56 42 46 58 55 56 32 51 35 42 42 44 4e } //15 RR3IL6YJTKWSXB3I6KRTAAVBFXUV2Q5BBDN
		$a_01_1 = {54 6f 74 61 6c 56 69 73 69 62 6c 65 4d 65 6d 6f 72 79 53 69 7a 65 3d 28 25 64 2b 29 } //5 TotalVisibleMemorySize=(%d+)
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}