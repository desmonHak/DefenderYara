
rule _#do_vmmgrow_rescan{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 3a 00 8b 7d 0c 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_2{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 39 c1 7e 12 48 89 c2 83 e2 03 41 8a 14 10 30 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_3{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 8b 45 08 0f 85 ?? ?? ff ff 90 09 02 00 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_4{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c1 e8 2c 06 00 00 00 00 39 74 00 00 00 00 00 57 00 77 48 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_5{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 5a 8c 04 00 4c 63 c3 31 d2 48 89 c1 ff 15 44 8c 04 00 49 89 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_6{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 a3 07 00 00 00 65 00 6e 65 75 69 52 49 00 44 70 ?? 4e 00 00 00 34 00 33 6f ?? 77 4f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_7{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 38 c9 c2 10 00 0f 85 ?? ?? ff ff } //1
		$a_03_1 = {66 8b 08 81 f1 4d e0 00 00 0f 84 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_8{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 f4 01 00 00 68 99 00 00 00 } //2
		$a_01_1 = {81 7d dc 68 58 4d 56 } //2
		$a_03_2 = {68 6e 0f 00 00 6a 10 68 ?? ?? ?? ?? e8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=4
 
}
rule _#do_vmmgrow_rescan_9{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 37 00 00 [0-20] (7d|0f 8d) [0-20] 7f 02 00 00 [0-20] (7d|0f 8d) [0-20] 7f [0-20] (|) 7f 0f 8f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule _#do_vmmgrow_rescan_10{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 83 b8 18 01 00 00 06 74 0e 83 b8 18 01 00 00 0a 74 50 e9 3f 01 00 00 83 b8 1c 01 00 00 01 74 1f 83 b8 1c 01 00 00 02 0f 84 ce 00 00 00 83 b8 1c 01 00 00 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_11{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 00 41 00 62 00 6f 00 75 00 74 00 20 00 45 00 76 00 65 00 6e 00 74 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 2e 00 2e 00 2e 00 00 00 } //1
		$a_01_1 = {45 00 76 00 65 00 6e 00 74 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule _#do_vmmgrow_rescan_12{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 40 00 00 00 ff ?? 89 ?? [0-02] 81 ?? ?? ?? ?? ?? [0-02] 89 ?? [0-02] 68 } //10
		$a_03_1 = {74 04 89 ec 5d c3 90 09 0b 00 89 ?? c1 ?? ?? 81 ?? ?? 00 00 00 } //1
		$a_03_2 = {74 04 89 ec 5d c3 90 09 07 00 89 ?? c1 ?? ?? 85 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}
rule _#do_vmmgrow_rescan_13{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {c9 c2 10 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
		$a_03_1 = {c9 c2 0c 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
		$a_03_2 = {c9 c2 14 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
		$a_03_3 = {c9 c2 1c 00 0f 85 ?? ?? ff ff 90 09 05 00 8b ?? ?? 81 } //1
		$a_03_4 = {c9 c2 00 00 85 ff 75 90 09 05 00 8b ?? ?? 81 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=1
 
}
rule _#do_vmmgrow_rescan_14{
	meta:
		description = "!#do_vmmgrow_rescan,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 65 6c 33 32 68 6b 65 72 6e } //1 hel32hkern
		$a_01_1 = {68 6c 6c 6f 63 68 75 61 6c 61 68 76 69 72 74 } //1 hllochualahvirt
		$a_01_2 = {68 72 6f 74 65 68 75 61 6c 70 68 76 69 72 74 } //1 hrotehualphvirt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}