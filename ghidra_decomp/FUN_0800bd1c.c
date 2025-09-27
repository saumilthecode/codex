
void FUN_0800bd1c(int param_1,undefined4 param_2)

{
  if (*(code **)(param_1 + 0x18) != (code *)0x0) {
    (**(code **)(param_1 + 0x18))();
  }
  FUN_0800bc58(param_1,param_2);
  *(undefined4 *)(param_1 + 0x18) = DAT_0800bd38;
  return;
}

