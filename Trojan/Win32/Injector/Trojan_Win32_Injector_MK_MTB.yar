
rule Trojan_Win32_Injector_MK_MTB{
	meta:
		description = "Trojan:Win32/Injector.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 d8 f5 ff ff 36 c6 85 d9 f5 ff ff 36 c6 85 da f5 ff ff 36 88 95 db f5 ff ff } //15
		$a_01_1 = {c6 85 f2 f5 ff ff 33 c6 85 f3 f5 ff ff 35 c6 85 f4 f5 ff ff 6d c6 85 f5 f5 ff ff 57 c6 85 f6 f5 ff ff 68 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}