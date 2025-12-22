
rule Trojan_Win64_ShellCode_MK_MTB{
	meta:
		description = "Trojan:Win64/ShellCode.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 10 0f b6 40 05 88 45 fb 48 8b 45 10 0f b6 40 04 88 45 fa 0f b6 45 fb c1 e0 ?? 89 c2 0f b6 45 fa 09 d0 66 89 45 fc 0f b7 45 fc } //15
		$a_03_1 = {0f b7 55 fe b8 00 00 00 00 29 d0 c1 e0 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 00 3c 4c } //10
		$a_01_2 = {5b 2b 5d 20 4d 65 6d 6f 72 79 20 63 68 61 6e 67 65 64 20 74 6f 20 50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 } //5 [+] Memory changed to PAGE_EXECUTE_READ
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}