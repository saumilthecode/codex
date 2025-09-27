
undefined4 * FUN_08025da8(undefined4 *param_1,undefined2 param_2,undefined2 param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  *param_1 = 0;
  param_1[1] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[2] = 0;
  *(undefined2 *)(param_1 + 3) = param_2;
  param_1[0x19] = 0;
  *(undefined2 *)((int)param_1 + 0xe) = param_3;
  param_1[6] = 0;
  puVar2 = (undefined4 *)FUN_08026922(param_1 + 0x17,0,8);
  param_1[9] = DAT_08025e00;
  param_1[10] = DAT_08025e04;
  param_1[0xb] = DAT_08025e08;
  param_1[0xc] = DAT_08025e0c;
  puVar1 = DAT_08025e10;
  param_1[8] = param_1;
  if (((param_1 != puVar1) && (param_1 != puVar1 + 0x1a)) && (param_1 != puVar1 + 0x34)) {
    return puVar2;
  }
  return param_1 + 0x16;
}

