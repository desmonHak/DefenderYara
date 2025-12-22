
rule Ransom_Win32_Locky_VZV_MTB{
	meta:
		description = "Ransom:Win32/Locky.VZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 c2 0d 2a ca 32 cb 88 0c 07 8a c8 80 e1 1f 0f b6 d3 d3 c2 8b 4d ?? d1 c9 03 d1 8b c8 c1 c9 17 81 c1 68 2f 70 53 33 d1 40 89 55 ec 3b 46 10 72 } //5
		$a_81_1 = {5f 4c 6f 63 6b 79 5f 72 65 63 6f 76 65 72 5f 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 74 78 74 } //1 _Locky_recover_instructions.txt
		$a_81_2 = {2e 6c 6f 63 6b 79 } //1 .locky
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}