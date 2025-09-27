
void FUN_08008618(int *param_1,undefined4 param_2)

{
  int iVar1;
  
  FUN_080106a8(param_1 + 1);
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  param_1[0x23] = 0;
  *(undefined1 *)(param_1 + 0x1f) = 0;
  iVar1 = DAT_0800864c;
  *param_1 = DAT_0800864c;
  param_1[1] = iVar1 + 0x14;
  FUN_0801067a(param_1 + 1,param_2);
  return;
}

