
undefined4 * FUN_080106a8(undefined4 *param_1)

{
  undefined4 *puVar1;
  
  *param_1 = DAT_080106e8;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  puVar1 = param_1 + 9;
  do {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1 = puVar1 + 2;
  } while (puVar1 != param_1 + 0x19);
  param_1[0x19] = 8;
  param_1[0x1a] = param_1 + 9;
  FUN_08017594(param_1 + 0x1b);
  return param_1;
}

