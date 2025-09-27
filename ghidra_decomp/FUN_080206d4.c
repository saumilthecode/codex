
undefined4 * FUN_080206d4(undefined4 *param_1)

{
  *param_1 = DAT_080206f0;
  if ((int *)param_1[2] != (int *)0x0) {
    (**(code **)(*(int *)param_1[2] + 4))();
  }
  FUN_080088f8(param_1);
  return param_1;
}

