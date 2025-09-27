
int FUN_08009636(int param_1)

{
  if (*(code **)(param_1 + 0x18) != (code *)0x0) {
    (**(code **)(param_1 + 0x18))();
  }
  return param_1;
}

