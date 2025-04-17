//Threads:BSD -12

#ifndef FIXED_POINT_H
#define FIXED_POINT_H

/* 17.14 fixed-point representation */
#define F (1 << 14)

int int_to_fp(int n);                // n -> fixed-point
int fp_to_int(int x);               // fixed-point -> int (truncation)
int fp_to_int_round(int x);         // fixed-point -> int (rounding)

int add_fp(int x, int y);           // x + y
int sub_fp(int x, int y);           // x - y
int add_mixed(int x, int n);        // x + n
int sub_mixed(int x, int n);        // x - n

int mult_fp(int x, int y);          // x * y
int mult_mixed(int x, int n);       // x * n
int div_fp(int x, int y);           // x / y
int div_mixed(int x, int n);        // x / n

#endif /* fixed-point.h */
