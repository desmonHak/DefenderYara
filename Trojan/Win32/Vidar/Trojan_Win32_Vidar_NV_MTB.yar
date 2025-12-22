
rule Trojan_Win32_Vidar_NV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 c1 20 0f 45 f7 0f 45 f8 89 bc cc 5c 0b 00 00 31 d6 89 b4 cc 58 0b 00 00 f6 c1 0f 75 c5 } //2
		$a_01_1 = {c1 e6 05 8b bc 24 58 01 00 00 0f b7 9c 4c 58 09 00 00 01 fb 01 f3 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Vidar_NV_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ff 05 dc af 45 00 33 c0 5a 59 59 64 89 10 68 98 7a 45 } //3
		$a_03_1 = {83 c4 f0 b8 cc 7a 45 00 e8 ?? ?? ?? ?? a1 b4 9d 45 00 8b 00 e8 ?? ?? ?? ?? 8b 0d 48 9a 45 00 a1 b4 9d 45 00 8b 00 8b 15 14 75 45 00 e8 ?? ?? ?? ?? a1 b4 9d 45 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}