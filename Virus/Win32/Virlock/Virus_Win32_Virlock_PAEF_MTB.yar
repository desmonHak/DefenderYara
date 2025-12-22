
rule Virus_Win32_Virlock_PAEF_MTB{
	meta:
		description = "Virus:Win32/Virlock.PAEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 00 84 01 00 6a 00 e8 } //1
		$a_01_1 = {ba 19 00 00 00 8a 06 32 c2 90 88 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}