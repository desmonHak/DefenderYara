
rule Trojan_Win32_SusAAD_D{
	meta:
		description = "Trojan:Win32/SusAAD.D,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {52 65 63 6f 6e 65 72 61 74 6f 72 2e 65 78 65 } //Reconerator.exe  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_00_2 = {61 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 6c 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 61 00 } //-1 a453e881-26a8-4973-bl2e-76269e901d0a
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}