
undefined4 * FUN_080093fc(undefined4 *param_1)

{
  int iVar1;
  
  *param_1 = DAT_08009420;
  iVar1 = param_1[4];
  *(undefined4 *)(iVar1 + 0xc) = 0;
  *(undefined4 *)(iVar1 + 0x20) = 0;
  *(undefined4 *)(iVar1 + 0x28) = 0;
  *(undefined4 *)(iVar1 + 0x30) = 0;
  FUN_0800928e(param_1 + 3);
  FUN_08020460(param_1);
  return param_1;
}

