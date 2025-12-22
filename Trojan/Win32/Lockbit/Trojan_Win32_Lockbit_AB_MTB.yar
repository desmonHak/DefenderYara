
rule Trojan_Win32_Lockbit_AB_MTB{
	meta:
		description = "Trojan:Win32/Lockbit.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c7 c1 c0 07 33 f0 8b 44 24 28 03 c6 89 74 24 38 c1 c0 09 31 44 24 20 8b 44 24 20 03 c6 8b 74 24 34 c1 c0 0d 33 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}