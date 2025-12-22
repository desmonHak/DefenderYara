
rule Trojan_Win32_Zusy_AMB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be c8 6b c9 0d 02 ca 32 88 ?? ?? ?? ?? 88 4c 05 a0 40 83 f8 59 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zusy_AMB_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 89 85 f4 ?? ff ff 8b 85 f0 ?? ff ff 83 c0 2a 8b 8d 10 ?? ff ff 03 4d 94 33 c1 88 85 } //3
		$a_80_1 = {4f 62 61 6b 2e 64 6c 6c 20 6f 66 79 68 } //Obak.dll ofyh  1
		$a_80_2 = {55 64 75 7a 79 64 20 79 73 61 76 20 65 77 79 63 20 69 6b 6f 6c 79 7a } //Uduzyd ysav ewyc ikolyz  1
	condition:
		((#a_03_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}