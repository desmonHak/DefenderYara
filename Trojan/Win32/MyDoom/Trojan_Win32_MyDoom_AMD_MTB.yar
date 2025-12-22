
rule Trojan_Win32_MyDoom_AMD_MTB{
	meta:
		description = "Trojan:Win32/MyDoom.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 6a 1a 99 59 f7 f9 80 c2 61 88 54 3d e4 47 3b fe } //3
		$a_03_1 = {56 8b 35 54 10 50 00 57 8d 45 bc 68 f0 30 50 00 50 ff d6 8d 45 bc 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff } //2
		$a_01_2 = {8d 45 bc 68 d4 30 50 00 50 ff d6 8d 45 bc 50 57 ff 15 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}