#define D_API( x )  __typeof__( x ) * x
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define MODULE_SIZE(x)      ((PIMAGE_NT_HEADERS)((UINT_PTR)x + ((PIMAGE_DOS_HEADER)x)->e_lfanew))->OptionalHeader.SizeOfImage
#define DBREAK              __debugbreak()
#define DEREF( name )*(UINT_PTR *)(name)

#define U_PTR(x)   (UINT_PTR)x


#define SPOOF_CALL_X(Inst, function) \
    SpoofCall(Inst, (PVOID)(function), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_A(Inst, function, a) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_B(Inst, function, a, b) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_C(Inst, function, a, b, c) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_D(Inst, function, a, b, c, d) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_E(Inst, function, a, b, c, d, e) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), NULL, NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_F(Inst, function, a, b, c, d, e, f) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), NULL, NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_G(Inst, function, a, b, c, d, e, f, g) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), NULL, NULL, NULL, NULL, NULL)

#define SPOOF_CALL_H(Inst, function, a, b, c, d, e, f, g, h) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), NULL, NULL, NULL, NULL)

#define SPOOF_CALL_I(Inst, function, a, b, c, d, e, f, g, h, i) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), NULL, NULL, NULL)

#define SPOOF_CALL_J(Inst, function, a, b, c, d, e, f, g, h, i, j) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), NULL, NULL)

#define SPOOF_CALL_K(Inst, function, a, b, c, d, e, f, g, h, i, j, k) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), NULL)

#define SPOOF_CALL_L(Inst, function, a, b, c, d, e, f, g, h, i, j, k, l) \
    SpoofCall(Inst, (PVOID)(function), (PVOID)(a), (PVOID)(b), (PVOID)(c), (PVOID)(d), (PVOID)(e), (PVOID)(f), (PVOID)(g), (PVOID)(h), (PVOID)(i), (PVOID)(j), (PVOID)(k), (PVOID)(l))

#define SPOOF_CALL_MACRO_CHOOSER(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME

#define SPOOF_CALL(Inst, function, ...) \
    SPOOF_CALL_MACRO_CHOOSER(__VA_ARGS__, \
        SPOOF_CALL_L, SPOOF_CALL_K, SPOOF_CALL_J, SPOOF_CALL_I, \
        SPOOF_CALL_H, SPOOF_CALL_G, SPOOF_CALL_F, SPOOF_CALL_E, \
        SPOOF_CALL_D, SPOOF_CALL_C, SPOOF_CALL_B, SPOOF_CALL_A, \
        SPOOF_CALL_X)(Inst, function, __VA_ARGS__)