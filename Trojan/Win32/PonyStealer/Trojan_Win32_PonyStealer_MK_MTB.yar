
rule Trojan_Win32_PonyStealer_MK_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 38 00 00 00 00 00 ff cc 31 00 31 a4 4d 97 89 80 8b 5d 49 b0 f7 00 c3 } //15
		$a_01_1 = {4b b1 b7 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 } //10
		$a_01_2 = {73 68 65 74 68 2e 64 6c 6c } //5 sheth.dll
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}