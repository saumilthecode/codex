
void FUN_08010e94(undefined4 *param_1,int param_2)

{
  *param_1 = DAT_08010ec4;
  if (param_2 != 0) {
    param_2 = 1;
  }
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[1] = param_2;
  *(undefined2 *)(param_1 + 4) = 0;
  *(undefined1 *)((int)param_1 + 0x12) = 0;
  param_1[0xd] = 0;
  *(undefined1 *)((int)param_1 + 0x43) = 0;
  return;
}

