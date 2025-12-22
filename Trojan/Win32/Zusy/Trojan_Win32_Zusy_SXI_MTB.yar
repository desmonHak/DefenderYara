
rule Trojan_Win32_Zusy_SXI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 e9 39 88 88 ?? ?? ?? ?? 40 3b c2 7c eb } //3
		$a_03_1 = {8d 49 00 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 8d 8d a8 fe ff ff 51 56 8b f8 ff 15 ?? ?? ?? ?? 8d 47 fe 83 f8 03 } //2
		$a_80_2 = {45 3a 5c 56 53 32 30 31 30 5c 56 43 5c 69 6e 63 6c 75 64 65 5c } //E:\VS2010\VC\include\  1
		$a_80_3 = {2d 3e 20 48 61 72 64 20 64 69 73 6b } //-> Hard disk  1
		$a_80_4 = {2d 3e 20 43 44 2f 44 56 44 } //-> CD/DVD  1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=8
 
}