
rule Trojan_BAT_Amadey_MR_MTB{
	meta:
		description = "Trojan:BAT/Amadey.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0b 11 0c 91 13 0d 11 08 20 1f 3f 5e 00 5a 11 0d 58 13 08 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 de } //10
		$a_01_1 = {24 64 34 61 63 61 38 35 63 2d 37 31 32 34 2d 34 37 33 64 2d 61 32 65 63 2d 32 36 39 35 66 64 66 30 38 38 38 65 } //5 $d4aca85c-7124-473d-a2ec-2695fdf0888e
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}