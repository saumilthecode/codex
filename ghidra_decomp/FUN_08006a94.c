
int FUN_08006a94(int param_1)

{
  undefined4 in_cr8;
  undefined4 in_cr9;
  undefined4 in_cr10;
  undefined4 in_cr11;
  
  coprocessor_store(1,in_cr8,param_1);
  coprocessor_store(1,in_cr9,param_1 + 4);
  coprocessor_store(1,in_cr10,param_1 + 8);
  coprocessor_store(1,in_cr11,param_1 + 0xc);
  return param_1 + 0x10;
}

