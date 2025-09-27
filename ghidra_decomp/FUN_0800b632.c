
void FUN_0800b632(int param_1,byte *param_2,byte *param_3,undefined4 *param_4)

{
  for (; param_2 < param_3; param_2 = param_2 + 1) {
    *param_4 = *(undefined4 *)(param_1 + (*param_2 + 0x24) * 4);
    param_4 = param_4 + 1;
  }
  return;
}

