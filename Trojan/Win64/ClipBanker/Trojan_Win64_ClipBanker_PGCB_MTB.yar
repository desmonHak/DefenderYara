
rule Trojan_Win64_ClipBanker_PGCB_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.PGCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 54 36 61 69 58 6b 59 64 59 47 74 37 4c 63 72 4a 44 6b 47 34 70 62 69 4a 77 44 47 63 41 62 31 57 79 00 00 00 00 00 00 44 52 41 52 4b 78 6d 68 42 75 44 4d 61 5a 57 73 72 4a 68 6e 67 77 79 6b 69 79 76 72 77 62 32 72 52 4a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}