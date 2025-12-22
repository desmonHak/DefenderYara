
rule Trojan_Win32_Injector_KK_MTB{
	meta:
		description = "Trojan:Win32/Injector.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 72 31 e3 ee 09 f6 e8 ?? ?? ?? ?? bf 1b c8 85 31 31 11 bf 45 b7 b6 28 01 f7 21 ff 81 c1 02 00 00 00 81 ef e8 53 06 59 4e 21 ff 39 c1 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}