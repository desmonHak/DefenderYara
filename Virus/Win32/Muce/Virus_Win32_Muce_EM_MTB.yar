
rule Virus_Win32_Muce_EM_MTB{
	meta:
		description = "Virus:Win32/Muce.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 f7 8a 04 16 30 03 43 41 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}