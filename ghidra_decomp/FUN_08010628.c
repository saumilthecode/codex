
void FUN_08010628(int param_1,uint param_2)

{
  if (*(int *)(param_1 + 0x7c) == 0) {
    param_2 = param_2 | 1;
  }
  *(uint *)(param_1 + 0x14) = param_2;
  if ((param_2 & *(uint *)(param_1 + 0x10)) != 0) {
    FUN_08021998(DAT_08010644);
  }
  return;
}

