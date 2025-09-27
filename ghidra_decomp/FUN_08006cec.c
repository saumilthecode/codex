
void FUN_08006cec(int *param_1)

{
  if ((int *)*param_1 != param_1 + 2) {
    thunk_FUN_080249c4((int *)*param_1,param_1[2] + 1);
    return;
  }
  return;
}

