
undefined4 FUN_0801f0da(int *param_1)

{
  code *pcVar1;
  
  if (*param_1 << 0x1f < 0) {
    return 0;
  }
  if (*(char *)((int)param_1 + 1) != '\0') {
                    /* WARNING: Does not return */
    pcVar1 = (code *)software_udf(0xff,0x801f0e6);
    (*pcVar1)();
  }
  *(undefined1 *)((int)param_1 + 1) = 1;
  return 1;
}

