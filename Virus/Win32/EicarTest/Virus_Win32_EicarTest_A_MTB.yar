
rule Virus_Win32_EicarTest_A_MTB{
	meta:
		description = "Virus:Win32/EicarTest.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 2f 34 6e 53 2f 34 2a 53 2f 34 } //1 S/4nS/4*S/4
	condition:
		((#a_01_0  & 1)*1) >=1
 
}