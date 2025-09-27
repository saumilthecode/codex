
void FUN_08025ec4(int param_1)

{
  FUN_08025eac();
  if (*(int *)(param_1 + 0x20) == 0) {
    *(undefined4 *)(param_1 + 0x20) = DAT_08025eec;
    if (*DAT_08025ef0 == 0) {
      FUN_08025e6c();
    }
  }
  FUN_08028654(DAT_08025ec0);
  return;
}

