
rule Trojan_Win64_GhostRat_HB_MTB{
	meta:
		description = "Trojan:Win64/GhostRat.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 00 70 00 44 00 61 00 74 00 65 00 73 00 5f 00 69 00 6e 00 66 00 6f 00 } //6 IpDates_info
		$a_01_1 = {25 00 73 00 2d 00 25 00 30 00 34 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 2e 00 64 00 6d 00 70 00 } //10 %s-%04d%02d%02d-%02d%02d%02d.dmp
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*10) >=16
 
}