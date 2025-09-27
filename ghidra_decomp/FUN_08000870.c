
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_08000870(int param_1)

{
  if (0xffffff < param_1 - 1U) {
    return 1;
  }
  _DAT_e000e014 = param_1 - 1U;
  *(undefined1 *)(DAT_0800089c + 0x23) = 0xf0;
  _DAT_e000e018 = 0;
  _DAT_e000e010 = 7;
  return 0;
}

