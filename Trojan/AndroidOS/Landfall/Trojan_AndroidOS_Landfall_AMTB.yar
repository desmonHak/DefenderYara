
rule Trojan_AndroidOS_Landfall_AMTB{
	meta:
		description = "Trojan:AndroidOS/Landfall!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {43 4d 44 5f 45 58 45 43 5f 46 41 49 4c 5f 54 4f 5f 47 45 54 5f 58 50 4f 53 45 44 5f 46 52 41 4d 45 57 4f 52 4b 5f 53 54 41 54 55 53 } //CMD_EXEC_FAIL_TO_GET_XPOSED_FRAMEWORK_STATUS  1
		$a_80_1 = {44 45 58 5f 4c 4f 41 44 5f 4d 45 4d 5f 4c 4f 41 44 5f 43 4c 53 5f 4e 4f 54 5f 46 4f 55 4e 44 } //DEX_LOAD_MEM_LOAD_CLS_NOT_FOUND  1
		$a_80_2 = {44 45 58 5f 4c 4f 41 44 5f 44 49 53 4b 5f 43 41 43 48 45 5f 4e 4f 54 5f 41 43 43 45 53 53 49 42 4c 45 } //DEX_LOAD_DISK_CACHE_NOT_ACCESSIBLE  1
		$a_80_3 = {43 4d 44 5f 55 4e 49 4e 53 54 5f 50 45 52 53 49 53 54 45 4e 43 59 5f 46 41 49 4c 5f 55 4e 4c 49 4e 4b 5f 50 41 59 4c 4f 41 44 } //CMD_UNINST_PERSISTENCY_FAIL_UNLINK_PAYLOAD  1
		$a_80_4 = {75 69 64 3d 25 64 2c 20 69 6e 63 72 65 6d 65 6e 74 61 6c 5f 62 75 69 6c 64 3a 20 25 73 2c 20 72 75 6e 6e 65 72 3a 20 25 73 } //uid=%d, incremental_build: %s, runner: %s  1
		$a_80_5 = {62 72 69 64 67 65 5f 68 65 61 64 } //bridge_head  1
		$a_80_6 = {63 6e 63 5f 68 6f 73 74 6e 61 6d 65 } //cnc_hostname  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}