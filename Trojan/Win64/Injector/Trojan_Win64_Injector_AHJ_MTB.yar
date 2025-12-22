
rule Trojan_Win64_Injector_AHJ_MTB{
	meta:
		description = "Trojan:Win64/Injector.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 8d c4 fe ff ff 48 8b d1 48 c1 e2 08 48 03 d1 0f b7 8d c4 fe ff ff 48 33 ca 48 33 c8 } //10
		$a_00_1 = {48 03 d0 48 63 85 1c ff ff ff 48 03 d0 48 63 85 18 ff ff ff 48 03 d0 48 03 95 10 ff ff ff 48 33 95 28 ff ff ff 48 87 11 48 } //30
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*30) >=40
 
}