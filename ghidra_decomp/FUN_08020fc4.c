
undefined4 FUN_08020fc4(undefined4 *param_1,uint param_2)

{
  short *psVar1;
  
  psVar1 = (short *)*param_1;
  if (param_2 < 0x10000) {
    if ((short *)param_1[1] == psVar1) {
      return 0;
    }
    *param_1 = psVar1 + 1;
    *psVar1 = (short)param_2;
  }
  else {
    if ((uint)((int)param_1[1] - (int)psVar1) < 3) {
      return 0;
    }
    *psVar1 = (short)(param_2 >> 10) + -0x2840;
    *param_1 = psVar1 + 2;
    psVar1[1] = (ushort)((param_2 << 0x16) >> 0x16) + 0xdc00;
  }
  return 1;
}

