
rule Trojan_BAT_NanoCore_AMTB{
	meta:
		description = "Trojan:BAT/NanoCore!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {24 37 39 39 36 34 46 34 38 2d 43 41 32 38 2d 34 41 38 38 2d 39 36 35 30 2d 31 35 36 34 31 31 37 30 35 39 44 33 } //$79964F48-CA28-4A88-9650-1564117059D3  3
		$a_80_1 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 33 2e 4d 6f 6e 6f 43 65 63 69 6c } //ConsoleApplication3.MonoCecil  1
		$a_80_2 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 33 2e 65 78 65 } //ConsoleApplication3.exe  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}