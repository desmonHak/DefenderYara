
rule Trojan_Win32_ColdFire_A{
	meta:
		description = "Trojan:Win32/ColdFire.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_1 = {63 6f 6c 64 66 69 72 65 2e 65 78 65 20 } //coldfire.exe   1
		$a_00_2 = {39 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 61 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 79 00 } //-1 9453e881-26a8-4973-ba2e-76269e901d0y
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}