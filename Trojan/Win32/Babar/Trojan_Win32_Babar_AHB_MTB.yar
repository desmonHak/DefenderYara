
rule Trojan_Win32_Babar_AHB_MTB{
	meta:
		description = "Trojan:Win32/Babar.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f8 8b d8 c1 ef ?? c1 eb ?? 89 45 f8 21 75 f8 89 45 f4 23 fe 23 de c1 6d f4 18 } //30
		$a_01_1 = {89 45 ec 89 7d f0 89 7d e8 89 7d fc 39 79 08 7e } //10
		$a_01_2 = {63 3a 5c 6c 6f 67 5f 25 73 2e 74 78 74 } //20 c:\log_%s.txt
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20) >=60
 
}