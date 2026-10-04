static int ej_get_operation_mode(int eid, webs_t wp, int argc, char **argv)
{
	int sw_mode, wlc_express, wlc_psta;
	int mlo_rp, mlo_mb;
	char ui_sw_mode[8];

	sw_mode = nvram_get_int("sw_mode");
	wlc_express = nvram_get_int("wlc_express");
	wlc_psta = nvram_get_int("wlc_psta");
	mlo_rp = nvram_get_int("mlo_rp");
	mlo_mb = nvram_get_int("mlo_mb");

	if (
		sw_mode == 2 && wlc_psta == 2 && mlo_rp == 1
	){
		strlcpy(ui_sw_mode, "rp", sizeof(ui_sw_mode));
	} 
	else if (
		sw_mode == 3 && wlc_psta == 2 && mlo_mb == 1
        ){
                strlcpy(ui_sw_mode, "mb", sizeof(ui_sw_mode));
        }
	else if (
		(((sw_mode == 2 && wlc_psta == 0) || (sw_mode == 3 && wlc_psta == 2)) && wlc_express == 0) ||
		(mlo_rp == 1)
	){
		strlcpy(ui_sw_mode, "rp", sizeof(ui_sw_mode));
	}
	else if (
		(sw_mode == 3 && wlc_psta == 1 && wlc_express == 0) ||
		(sw_mode == 3 && wlc_psta == 3 && wlc_express == 0) ||
		(sw_mode == 2 && wlc_psta == 1 && wlc_express == 0) 
	){
		strlcpy(ui_sw_mode, "mb", sizeof(ui_sw_mode));
	}
	else if (
		sw_mode == 3 && wlc_psta == 0
	){
		strlcpy(ui_sw_mode, "ap", sizeof(ui_sw_mode));
	}
	else if (
		sw_mode == 2 && wlc_psta == 0 && wlc_express == 1
	){
		strlcpy(ui_sw_mode, "ew2", sizeof(ui_sw_mode)); // Express Way 2G
	}
	else if (
		sw_mode == '2' && wlc_psta == '0' && wlc_express == '2'
	){
		strlcpy(ui_sw_mode, "ew5", sizeof(ui_sw_mode)); // Express Way 5G
	}
	else if (
		sw_mode == '5'
	){
		strlcpy(ui_sw_mode, "hs", sizeof(ui_sw_mode)); // Hotspot
	}
	else if (wisp_mode()) {
		strlcpy(ui_sw_mode, "wisp", sizeof(ui_sw_mode));
	}
	else {
		strlcpy(ui_sw_mode, "rt", sizeof(ui_sw_mode));
	}

	websWrite(wp, "\"%s\"", ui_sw_mode);
	return 0;
}
