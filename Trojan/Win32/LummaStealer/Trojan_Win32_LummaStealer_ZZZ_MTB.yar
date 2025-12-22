
rule Trojan_Win32_LummaStealer_ZZZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZZZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a6 e5 44 59 84 85 09 27 2b ab fb 50 4f 45 8a 17 76 fb 9c bf c0 13 0b ac 93 95 01 43 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}