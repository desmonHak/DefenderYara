
rule Trojan_Win64_Rhadamanthys_RR_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c0 90 52 48 8d 12 5a 4c 89 c0 66 90 80 30 72 48 89 c9 48 87 db 48 83 c0 01 48 39 c8 75 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}