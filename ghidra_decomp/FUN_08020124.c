
undefined4 * FUN_08020124(undefined4 *param_1)

{
  *param_1 = DAT_08020140;
  if ((int *)param_1[2] != (int *)0x0) {
    (**(code **)(*(int *)param_1[2] + 4))();
  }
  FUN_080088f8(param_1);
  return param_1;
}

