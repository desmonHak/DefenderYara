
rule Trojan_Win32_GuLoader_KH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.KH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {75 64 76 61 6c 67 73 62 65 68 61 6e 64 6c 65 72 2e 73 6b 6a } //1 udvalgsbehandler.skj
		$a_81_1 = {62 79 6f 72 6b 65 73 74 65 72 2e 68 79 70 } //1 byorkester.hyp
		$a_81_2 = {63 6c 61 73 73 69 63 61 6c 6c 79 2e 6b 61 6c } //1 classically.kal
		$a_81_3 = {72 75 6e 64 73 6b 61 61 72 65 6e 2e 64 6c 6c } //1 rundskaaren.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}