
rule Trojan_Win64_AsyncRat_ATA_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.ATA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 44 24 20 0f b6 4c 24 48 48 8b 54 24 40 0f be 04 02 33 c1 48 63 4c 24 20 48 8b 54 24 40 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}