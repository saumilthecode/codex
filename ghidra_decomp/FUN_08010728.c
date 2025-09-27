
undefined4 * FUN_08010728(undefined4 *param_1)

{
  *param_1 = DAT_0801075c;
  FUN_080106ec(param_1,0);
  FUN_08010706(param_1);
  if ((undefined4 *)param_1[0x1a] != param_1 + 9) {
    if ((undefined4 *)param_1[0x1a] != (undefined4 *)0x0) {
      thunk_FUN_080249c4();
    }
    param_1[0x1a] = 0;
  }
  FUN_080089f4(param_1 + 0x1b);
  return param_1;
}

