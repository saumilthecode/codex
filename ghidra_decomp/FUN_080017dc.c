
void FUN_080017dc(int param_1,int param_2,int param_3)

{
  if (param_3 == 0) {
    param_2 = param_2 << 0x10;
  }
  *(int *)(param_1 + 0x18) = param_2;
  return;
}

