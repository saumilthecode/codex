
void FUN_08010f84(undefined4 *param_1,int param_2)

{
  *param_1 = DAT_08010fa8;
  if (param_2 != 0) {
    param_2 = 1;
  }
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[1] = param_2;
  *(undefined1 *)(param_1 + 4) = 0;
  *(undefined2 *)(param_1 + 9) = 0;
  *(undefined1 *)(param_1 + 0x19) = 0;
  return;
}

