
rule Trojan_Win32_RadThief_MXZ_MTB{
	meta:
		description = "Trojan:Win32/RadThief.MXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 fc d2 f8 b0 8d 67 4b 9d 27 96 3c 27 a6 ab 43 bb 9e 63 14 c4 0e 1a 33 c2 cb bb 12 51 cf 6e 3d bb e7 5c 2d 06 8a e0 03 38 96 cb 52 1b 46 4d b6 9b ?? bf 64 61 e4 9e f2 cf 28 75 d6 1b 79 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}