
rule Ransom_Win32_DragonForce_SC_MTB{
	meta:
		description = "Ransom:Win32/DragonForce.SC!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 } //1 Public\log.log
		$a_01_1 = {50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 5f 00 77 00 68 00 69 00 74 00 65 00 2e 00 70 00 6e 00 67 00 } //1 Public\wallpaper_white.png
		$a_01_2 = {2e 00 64 00 72 00 61 00 67 00 6f 00 6e 00 66 00 6f 00 72 00 63 00 65 00 5f 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 .dragonforce_encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}