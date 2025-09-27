
void FUN_0800a74c(int *param_1,int param_2)

{
  if (param_1 != DAT_0800a760) {
    param_1[2] = 0;
    *param_1 = param_2;
    *(undefined1 *)((int)param_1 + param_2 + 0xc) = 0;
  }
  return;
}

