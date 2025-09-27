
undefined4 * FUN_0800b3b4(undefined4 *param_1,int param_2,byte param_3,int param_4)

{
  int iVar1;
  bool bVar2;
  
  iVar1 = param_4;
  if (param_4 != 0) {
    iVar1 = 1;
  }
  param_1[1] = iVar1;
  *param_1 = DAT_0800b404;
  iVar1 = DAT_0800b408;
  bVar2 = param_2 == 0;
  if (bVar2) {
    param_2 = DAT_0800b408;
  }
  param_3 = param_3 & 1;
  if (bVar2) {
    param_3 = 0;
  }
  param_1[4] = 0;
  param_1[5] = 0;
  *(byte *)(param_1 + 3) = param_3;
  param_1[6] = param_2;
  FUN_08026922((int)param_1 + 0x1d,0,0x100,iVar1,param_4);
  *(undefined1 *)(param_1 + 7) = 0;
  FUN_08026922((int)param_1 + 0x11d,0,0x100);
  *(undefined1 *)((int)param_1 + 0x21d) = 0;
  return param_1;
}

