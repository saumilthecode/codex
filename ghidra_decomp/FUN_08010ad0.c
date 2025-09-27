
undefined4 * FUN_08010ad0(undefined4 *param_1)

{
  *param_1 = DAT_08010b00;
  if (*(char *)(param_1 + 0x19) != '\0') {
    if (param_1[2] != 0) {
      thunk_FUN_080249c4();
    }
    if (param_1[5] != 0) {
      thunk_FUN_080249c4();
    }
    if (param_1[7] != 0) {
      thunk_FUN_080249c4();
    }
  }
  FUN_080088f8(param_1);
  return param_1;
}

