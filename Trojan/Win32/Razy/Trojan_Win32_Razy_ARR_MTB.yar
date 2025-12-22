
rule Trojan_Win32_Razy_ARR_MTB{
	meta:
		description = "Trojan:Win32/Razy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 41 49 31 c9 49 c1 e9 } //2
		$a_01_1 = {8b c3 0f b6 0c 3b 99 f7 7d 10 8b 45 0c 0f b6 04 02 } //10
		$a_03_2 = {43 4b 4b c1 eb ?? 43 4b 4b c1 eb ?? 31 db 43 83 c3 } //8
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*10+(#a_03_2  & 1)*8) >=20
 
}