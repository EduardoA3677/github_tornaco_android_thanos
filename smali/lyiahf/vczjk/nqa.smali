.class public abstract Llyiahf/vczjk/nqa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static OooO:Llyiahf/vczjk/qv3;

.field public static final OooO00o:[Ljava/lang/Object;

.field public static final OooO0O0:[[Ljava/lang/String;

.field public static final OooO0OO:[[Ljava/lang/String;

.field public static final OooO0Oo:[Ljava/lang/StackTraceElement;

.field public static final OooO0o:Llyiahf/vczjk/yu2;

.field public static final OooO0o0:Llyiahf/vczjk/wj7;

.field public static final synthetic OooO0oO:I

.field public static final synthetic OooO0oo:I

.field public static final synthetic OooOO0:I

.field public static final synthetic OooOO0O:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 5

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    sput-object v0, Llyiahf/vczjk/nqa;->OooO00o:[Ljava/lang/Object;

    const-string v0, "\""

    const-string v1, "&quot;"

    filled-new-array {v0, v1}, [Ljava/lang/String;

    move-result-object v0

    const-string v1, "&"

    const-string v2, "&amp;"

    filled-new-array {v1, v2}, [Ljava/lang/String;

    move-result-object v1

    const-string v2, "<"

    const-string v3, "&lt;"

    filled-new-array {v2, v3}, [Ljava/lang/String;

    move-result-object v2

    const-string v3, ">"

    const-string v4, "&gt;"

    filled-new-array {v3, v4}, [Ljava/lang/String;

    move-result-object v3

    filled-new-array {v0, v1, v2, v3}, [[Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/nqa;->OooO0O0:[[Ljava/lang/String;

    const-string v0, "\'"

    const-string v1, "&apos;"

    filled-new-array {v0, v1}, [Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0}, [[Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/nqa;->OooO0OO:[[Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/StackTraceElement;

    sput-object v0, Llyiahf/vczjk/nqa;->OooO0Oo:[Ljava/lang/StackTraceElement;

    new-instance v0, Llyiahf/vczjk/wj7;

    const/4 v1, 0x0

    const/high16 v2, 0x41200000    # 10.0f

    invoke-direct {v0, v1, v1, v2, v2}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/nqa;->OooO0o0:Llyiahf/vczjk/wj7;

    new-instance v0, Llyiahf/vczjk/yu2;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/yu2;-><init>(II)V

    sput-object v0, Llyiahf/vczjk/nqa;->OooO0o:Llyiahf/vczjk/yu2;

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/r58;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 8

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, 0x31a55716

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p3

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    and-int/lit8 v1, v0, 0x13

    const/16 v2, 0x12

    if-ne v1, v2, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_3
    :goto_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, v2, :cond_4

    new-instance v1, Llyiahf/vczjk/rt3;

    const/16 v2, 0xc

    invoke-direct {v1, v2}, Llyiahf/vczjk/rt3;-><init>(I)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-static {p2}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v2

    if-eqz v2, :cond_7

    sget-object v3, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v4, Llyiahf/vczjk/t40;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v5

    new-instance v6, Llyiahf/vczjk/sw7;

    const/16 v7, 0x13

    invoke-direct {v6, v7}, Llyiahf/vczjk/sw7;-><init>(I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v3

    invoke-virtual {v6, v3, v1}, Llyiahf/vczjk/sw7;->OooO0o0(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v6}, Llyiahf/vczjk/sw7;->OooO0o()Llyiahf/vczjk/a0;

    move-result-object v1

    instance-of v3, v2, Llyiahf/vczjk/om3;

    if-eqz v3, :cond_5

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/om3;

    invoke-interface {v3}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v3

    goto :goto_3

    :cond_5
    sget-object v3, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_3
    invoke-static {v2, v5, v1, v3}, Llyiahf/vczjk/eo6;->OooO(Llyiahf/vczjk/lha;Llyiahf/vczjk/gf4;Llyiahf/vczjk/hha;Llyiahf/vczjk/os1;)Llyiahf/vczjk/dha;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t40;

    new-instance v2, Llyiahf/vczjk/rc0;

    invoke-direct {v2, p0}, Llyiahf/vczjk/rc0;-><init>(Llyiahf/vczjk/o58;)V

    iput-object v2, v1, Llyiahf/vczjk/t40;->OooO0OO:Llyiahf/vczjk/rc0;

    and-int/lit8 v2, v0, 0x70

    shl-int/lit8 v0, v0, 0x6

    and-int/lit16 v0, v0, 0x380

    or-int/2addr v0, v2

    iget-object v1, v1, Llyiahf/vczjk/t40;->OooO0O0:Ljava/lang/String;

    invoke-virtual {p0, v1, p1, p2, v0}, Llyiahf/vczjk/r58;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_4
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_6

    new-instance v0, Llyiahf/vczjk/e2;

    const/16 v1, 0x14

    invoke-direct {v0, p0, p1, p3, v1}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void

    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO00o(Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 11

    const-string v0, "text"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onClick"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v8, p2

    check-cast v8, Llyiahf/vczjk/zf1;

    const p2, 0x511bee7f

    invoke-virtual {v8, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    const/4 v0, 0x4

    if-eqz p2, :cond_0

    move p2, v0

    goto :goto_0

    :cond_0
    const/4 p2, 0x2

    :goto_0
    or-int/2addr p2, p3

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    const/16 v2, 0x20

    if-eqz v1, :cond_1

    move v1, v2

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr p2, v1

    and-int/lit8 v1, p2, 0x13

    const/16 v3, 0x12

    if-ne v1, v3, :cond_3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_3
    :goto_2
    int-to-float v0, v0

    new-instance v6, Llyiahf/vczjk/di6;

    invoke-direct {v6, v0, v0, v0, v0}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    const v0, 0x4c5de2

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 p2, p2, 0x70

    const/4 v0, 0x0

    if-ne p2, v2, :cond_4

    const/4 p2, 0x1

    goto :goto_3

    :cond_4
    move p2, v0

    :goto_3
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez p2, :cond_5

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, p2, :cond_6

    :cond_5
    new-instance v1, Llyiahf/vczjk/a5;

    const/4 p2, 0x7

    invoke-direct {v1, p2, p1}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance p2, Llyiahf/vczjk/v5;

    const/4 v0, 0x1

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/v5;-><init>(Ljava/lang/String;I)V

    const v0, 0x110f87bc

    invoke-static {v0, p2, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/high16 v9, 0x30c00000

    const/16 v10, 0x17e

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_7

    new-instance v0, Llyiahf/vczjk/b5;

    const/4 v1, 0x1

    invoke-direct {v0, p0, p1, p3, v1}, Llyiahf/vczjk/b5;-><init>(Ljava/lang/String;Llyiahf/vczjk/le3;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/v86;Llyiahf/vczjk/o4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 7

    move-object v4, p3

    check-cast v4, Llyiahf/vczjk/zf1;

    const p3, 0x1c5fd74b

    invoke-virtual {v4, p3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 p3, p4, 0x6

    const/4 v0, 0x4

    if-nez p3, :cond_2

    and-int/lit8 p3, p4, 0x8

    if-nez p3, :cond_0

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    goto :goto_0

    :cond_0
    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    :goto_0
    if-eqz p3, :cond_1

    move p3, v0

    goto :goto_1

    :cond_1
    const/4 p3, 0x2

    :goto_1
    or-int/2addr p3, p4

    goto :goto_2

    :cond_2
    move p3, p4

    :goto_2
    and-int/lit8 v1, p4, 0x30

    const/16 v2, 0x20

    if-nez v1, :cond_4

    invoke-virtual {v4, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    move v1, v2

    goto :goto_3

    :cond_3
    const/16 v1, 0x10

    :goto_3
    or-int/2addr p3, v1

    :cond_4
    and-int/lit16 v1, p4, 0x180

    if-nez v1, :cond_6

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    const/16 v1, 0x100

    goto :goto_4

    :cond_5
    const/16 v1, 0x80

    :goto_4
    or-int/2addr p3, v1

    :cond_6
    and-int/lit16 v1, p3, 0x93

    const/16 v3, 0x92

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eq v1, v3, :cond_7

    move v1, v5

    goto :goto_5

    :cond_7
    move v1, v6

    :goto_5
    and-int/lit8 v3, p3, 0x1

    invoke-virtual {v4, v3, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_d

    and-int/lit8 v1, p3, 0x70

    if-ne v1, v2, :cond_8

    move v1, v5

    goto :goto_6

    :cond_8
    move v1, v6

    :goto_6
    and-int/lit8 v2, p3, 0xe

    if-eq v2, v0, :cond_a

    and-int/lit8 v0, p3, 0x8

    if-eqz v0, :cond_9

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_9

    goto :goto_7

    :cond_9
    move v5, v6

    :cond_a
    :goto_7
    or-int v0, v1, v5

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_b

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, v0, :cond_c

    :cond_b
    new-instance v1, Llyiahf/vczjk/ul3;

    invoke-direct {v1, p1, p0}, Llyiahf/vczjk/ul3;-><init>(Llyiahf/vczjk/o4;Llyiahf/vczjk/v86;)V

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/ul3;

    new-instance v2, Llyiahf/vczjk/d07;

    sget-object v1, Llyiahf/vczjk/ic8;->OooOOO0:Llyiahf/vczjk/ic8;

    invoke-direct {v2, v6, v1, v6}, Llyiahf/vczjk/d07;-><init>(ZLlyiahf/vczjk/ic8;Z)V

    shl-int/lit8 p3, p3, 0x3

    and-int/lit16 p3, p3, 0x1c00

    or-int/lit16 v5, p3, 0x180

    const/4 v6, 0x2

    const/4 v1, 0x0

    move-object v3, p2

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/of;->OooO00o(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    goto :goto_8

    :cond_d
    move-object v3, p2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_8
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_e

    new-instance p3, Llyiahf/vczjk/xf;

    invoke-direct {p3, p0, p1, v3, p4}, Llyiahf/vczjk/xf;-><init>(Llyiahf/vczjk/v86;Llyiahf/vczjk/o4;Llyiahf/vczjk/ze3;I)V

    iput-object p3, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_e
    return-void
.end method

.method public static final OooO0OO(ILlyiahf/vczjk/rf1;)V
    .locals 12

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/zf1;

    const p1, 0x5ad924bc

    invoke-virtual {v3, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    if-nez p0, :cond_1

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v7, v3

    goto/16 :goto_1

    :cond_1
    :goto_0
    invoke-static {v3}, Llyiahf/vczjk/wr6;->OooOo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/yo9;

    move-result-object p1

    const/4 v10, 0x0

    invoke-static {p1, v3, v10}, Llyiahf/vczjk/dn8;->OooOOo(Llyiahf/vczjk/yo9;Llyiahf/vczjk/rf1;I)V

    invoke-static {v3}, Llyiahf/vczjk/zsa;->ooOO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/zh1;

    move-result-object v1

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->status_not_active:I

    invoke-static {v0, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v0

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->message_active_needed:I

    invoke-static {v2, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    const v4, 0x6e3c21fe

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v11, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v11, :cond_2

    new-instance v5, Llyiahf/vczjk/rt3;

    const/4 v6, 0x2

    invoke-direct {v5, v6}, Llyiahf/vczjk/rt3;-><init>(I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-static {v3, v10, v4}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v11, :cond_3

    new-instance v4, Llyiahf/vczjk/rt3;

    const/4 v6, 0x3

    invoke-direct {v4, v6}, Llyiahf/vczjk/rt3;-><init>(I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v4, 0x0

    move-object v7, v3

    move-object v3, v5

    const-string v5, ""

    const v8, 0x1b0c00

    const/16 v9, 0x10

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/zsa;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/zh1;Ljava/lang/Object;Llyiahf/vczjk/oe3;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    sget-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    const v2, -0x615d173a

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_4

    if-ne v3, v11, :cond_5

    :cond_4
    new-instance v3, Llyiahf/vczjk/km4;

    const/4 v2, 0x0

    invoke-direct {v3, p1, v1, v2}, Llyiahf/vczjk/km4;-><init>(Llyiahf/vczjk/yo9;Llyiahf/vczjk/zh1;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/ze3;

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v5, 0x1

    const/4 v1, 0x0

    const/4 v4, 0x0

    move-object v3, v7

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/so8;->OooOo0O(Llyiahf/vczjk/zl1;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_1
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_6

    new-instance v0, Llyiahf/vczjk/jm4;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/jm4;-><init>(II)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/ku5;Llyiahf/vczjk/r58;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 6

    check-cast p3, Llyiahf/vczjk/zf1;

    const v0, 0xdf2283d

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    and-int/lit16 v0, v0, 0x93

    const/16 v1, 0x92

    if-ne v0, v1, :cond_3

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    sget-object v0, Llyiahf/vczjk/c45;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/s35;->OooO00o:Landroidx/compose/runtime/OooO;

    invoke-virtual {v1, p0}, Landroidx/compose/runtime/OooO;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/y35;->OooO00o:Landroidx/compose/runtime/OooO;

    invoke-virtual {v2, p0}, Landroidx/compose/runtime/OooO;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v2

    filled-new-array {v0, v1, v2}, [Llyiahf/vczjk/ke7;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/b6;

    const/16 v2, 0x18

    invoke-direct {v1, v2, p1, p2}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v2, 0x6bd29b7d

    invoke-static {v2, v1, p3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    const/16 v2, 0x38

    invoke-static {v0, v1, p3, v2}, Llyiahf/vczjk/r02;->OooO0O0([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    :goto_3
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p3

    if-eqz p3, :cond_4

    new-instance v0, Llyiahf/vczjk/o0OO00OO;

    const/4 v5, 0x7

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o0OO00OO;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method

.method public static final OooO0o(Ljava/lang/String;Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/rf1;II)V
    .locals 18

    move-object/from16 v1, p0

    move-wide/from16 v5, p4

    move/from16 v8, p8

    const-string v0, "text"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v15, p7

    check-cast v15, Llyiahf/vczjk/zf1;

    const v0, -0x5832446

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, v8, 0x6

    const/4 v2, 0x2

    if-nez v0, :cond_1

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    or-int/2addr v0, v8

    goto :goto_1

    :cond_1
    move v0, v8

    :goto_1
    and-int/lit8 v3, p9, 0x2

    if-eqz v3, :cond_3

    or-int/lit8 v0, v0, 0x30

    :cond_2
    move-object/from16 v4, p1

    goto :goto_3

    :cond_3
    and-int/lit8 v4, v8, 0x30

    if-nez v4, :cond_2

    move-object/from16 v4, p1

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    const/16 v7, 0x20

    goto :goto_2

    :cond_4
    const/16 v7, 0x10

    :goto_2
    or-int/2addr v0, v7

    :goto_3
    and-int/lit16 v7, v8, 0x180

    move-wide/from16 v10, p2

    if-nez v7, :cond_6

    invoke-virtual {v15, v10, v11}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v7

    if-eqz v7, :cond_5

    const/16 v7, 0x100

    goto :goto_4

    :cond_5
    const/16 v7, 0x80

    :goto_4
    or-int/2addr v0, v7

    :cond_6
    and-int/lit16 v7, v8, 0xc00

    if-nez v7, :cond_8

    invoke-virtual {v15, v5, v6}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v7

    if-eqz v7, :cond_7

    const/16 v7, 0x800

    goto :goto_5

    :cond_7
    const/16 v7, 0x400

    :goto_5
    or-int/2addr v0, v7

    :cond_8
    and-int/lit8 v7, p9, 0x10

    if-eqz v7, :cond_a

    or-int/lit16 v0, v0, 0x6000

    :cond_9
    move/from16 v9, p6

    goto :goto_7

    :cond_a
    and-int/lit16 v9, v8, 0x6000

    if-nez v9, :cond_9

    move/from16 v9, p6

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v12

    if-eqz v12, :cond_b

    const/16 v12, 0x4000

    goto :goto_6

    :cond_b
    const/16 v12, 0x2000

    :goto_6
    or-int/2addr v0, v12

    :goto_7
    and-int/lit16 v12, v0, 0x2493

    const/16 v13, 0x2492

    if-ne v12, v13, :cond_d

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v12

    if-nez v12, :cond_c

    goto :goto_8

    :cond_c
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v2, v4

    move v7, v9

    goto :goto_d

    :cond_d
    :goto_8
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v12, v8, 0x1

    if-eqz v12, :cond_f

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v12

    if-eqz v12, :cond_e

    goto :goto_9

    :cond_e
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move v2, v9

    move-object v9, v4

    goto :goto_c

    :cond_f
    :goto_9
    if-eqz v3, :cond_10

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_a

    :cond_10
    move-object v3, v4

    :goto_a
    if-eqz v7, :cond_11

    int-to-float v2, v2

    :goto_b
    move-object v9, v3

    goto :goto_c

    :cond_11
    move v2, v9

    goto :goto_b

    :goto_c
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo0()V

    new-instance v3, Llyiahf/vczjk/k50;

    invoke-direct {v3, v5, v6, v1, v2}, Llyiahf/vczjk/k50;-><init>(JLjava/lang/String;F)V

    const v4, -0x6f667393

    invoke-static {v4, v3, v15}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v14

    shr-int/lit8 v0, v0, 0x3

    and-int/lit8 v3, v0, 0xe

    or-int/lit16 v3, v3, 0xc00

    and-int/lit8 v0, v0, 0x70

    or-int v16, v3, v0

    const/16 v17, 0x4

    const-wide/16 v12, 0x0

    invoke-static/range {v9 .. v17}, Llyiahf/vczjk/l50;->OooO00o(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    move v7, v2

    move-object v2, v9

    :goto_d
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v10

    if-eqz v10, :cond_12

    new-instance v0, Llyiahf/vczjk/i50;

    move-wide/from16 v3, p2

    move/from16 v9, p9

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/i50;-><init>(Ljava/lang/String;Llyiahf/vczjk/kl5;JJFII)V

    iput-object v0, v10, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void
.end method

.method public static final OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V
    .locals 11

    const-string v0, "text"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v8, p3

    check-cast v8, Llyiahf/vczjk/zf1;

    const p3, 0x7d1855c8

    invoke-virtual {v8, p3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    const/4 p3, 0x4

    goto :goto_0

    :cond_0
    const/4 p3, 0x2

    :goto_0
    or-int/2addr p3, p0

    and-int/lit8 v0, p1, 0x2

    if-eqz v0, :cond_1

    or-int/lit8 p3, p3, 0x30

    goto :goto_2

    :cond_1
    and-int/lit8 v1, p0, 0x30

    if-nez v1, :cond_3

    invoke-virtual {v8, p4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x20

    goto :goto_1

    :cond_2
    const/16 v1, 0x10

    :goto_1
    or-int/2addr p3, v1

    :cond_3
    :goto_2
    and-int/lit8 v1, p3, 0x13

    const/16 v2, 0x12

    if-ne v1, v2, :cond_5

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v1, p2

    goto :goto_4

    :cond_5
    :goto_3
    if-eqz v0, :cond_6

    sget-object p4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :cond_6
    move-object v2, p4

    sget-object p4, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, p4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Llyiahf/vczjk/x21;

    iget-wide v3, p4, Llyiahf/vczjk/x21;->OooO0OO:J

    const/16 p4, 0xa

    invoke-static {p4}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v5

    and-int/lit8 p4, p3, 0xe

    or-int/lit16 p4, p4, 0xc00

    and-int/lit8 p3, p3, 0x70

    or-int v9, p4, p3

    const/16 v10, 0x10

    const/4 v7, 0x0

    move-object v1, p2

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/nqa;->OooO0o(Ljava/lang/String;Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/rf1;II)V

    move-object p4, v2

    :goto_4
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_7

    new-instance p3, Llyiahf/vczjk/iu;

    invoke-direct {p3, v1, p4, p0, p1}, Llyiahf/vczjk/iu;-><init>(Ljava/lang/String;Llyiahf/vczjk/kl5;II)V

    iput-object p3, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method

.method public static final OooO0oO(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V
    .locals 27

    move-object/from16 v0, p2

    const-string v1, "text"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v1, p3

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x174bbed6

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v2, p1, 0x1

    const/4 v3, 0x4

    const/4 v4, 0x2

    if-eqz v2, :cond_0

    or-int/lit8 v5, p0, 0x6

    move v6, v5

    move-object/from16 v5, p4

    goto :goto_1

    :cond_0
    and-int/lit8 v5, p0, 0x6

    if-nez v5, :cond_2

    move-object/from16 v5, p4

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_1

    move v6, v3

    goto :goto_0

    :cond_1
    move v6, v4

    :goto_0
    or-int v6, p0, v6

    goto :goto_1

    :cond_2
    move-object/from16 v5, p4

    move/from16 v6, p0

    :goto_1
    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_3

    const/16 v7, 0x20

    goto :goto_2

    :cond_3
    const/16 v7, 0x10

    :goto_2
    or-int/2addr v6, v7

    and-int/lit8 v7, v6, 0x13

    const/16 v8, 0x12

    if-ne v7, v8, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v7

    if-nez v7, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v0, v1

    move-object v2, v5

    goto/16 :goto_6

    :cond_5
    :goto_3
    sget-object v7, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz v2, :cond_6

    move-object v2, v7

    goto :goto_4

    :cond_6
    move-object v2, v5

    :goto_4
    const/4 v5, 0x1

    int-to-float v8, v5

    sget-object v9, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/x21;

    iget-wide v10, v10, Llyiahf/vczjk/x21;->OooO00o:J

    sget-object v12, Llyiahf/vczjk/el8;->OooO00o:Llyiahf/vczjk/tv7;

    new-instance v13, Llyiahf/vczjk/gx8;

    invoke-direct {v13, v10, v11}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v10, Landroidx/compose/foundation/BorderModifierNodeElement;

    invoke-direct {v10, v8, v13, v12}, Landroidx/compose/foundation/BorderModifierNodeElement;-><init>(FLlyiahf/vczjk/gx8;Llyiahf/vczjk/qj8;)V

    invoke-interface {v2, v10}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v10

    invoke-static {v10, v8}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v10, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    const/4 v11, 0x0

    invoke-static {v10, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v11, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v1, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_7

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_7
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v1, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v1, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v12, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v12, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v12, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_9

    :cond_8
    invoke-static {v11, v1, v11, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v1, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    int-to-float v3, v3

    const/4 v8, 0x0

    invoke-static {v7, v3, v8, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v4, 0x9

    invoke-static {v4}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v7

    move-wide/from16 v25, v7

    move v8, v5

    move-wide/from16 v4, v25

    invoke-static {v1}, Llyiahf/vczjk/t51;->OooOoo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/ga3;

    move-result-object v7

    invoke-virtual {v1, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/x21;

    iget-wide v9, v9, Llyiahf/vczjk/x21;->OooO00o:J

    shr-int/lit8 v6, v6, 0x3

    and-int/lit8 v6, v6, 0xe

    or-int/lit16 v6, v6, 0x6030

    const/16 v17, 0x0

    const/16 v18, 0x0

    move/from16 v20, v6

    const/4 v6, 0x0

    move-object/from16 v19, v1

    move-object v11, v2

    move-object v1, v3

    move-wide v2, v9

    move v10, v8

    const-wide/16 v8, 0x0

    move v12, v10

    const/4 v10, 0x0

    move-object v13, v11

    move v14, v12

    const-wide/16 v11, 0x0

    move-object v15, v13

    const/4 v13, 0x0

    move/from16 v16, v14

    const/4 v14, 0x0

    move-object/from16 v21, v15

    const/4 v15, 0x0

    move/from16 v22, v16

    const/16 v16, 0x0

    move-object/from16 v23, v21

    const/16 v21, 0x0

    move/from16 v24, v22

    const v22, 0x3ff68

    invoke-static/range {v0 .. v22}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v0, v19

    const/4 v12, 0x1

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v2, v23

    :goto_6
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_a

    new-instance v0, Llyiahf/vczjk/iu;

    const/4 v4, 0x2

    move/from16 v1, p0

    move/from16 v3, p1

    move-object/from16 v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/iu;-><init>(ILjava/lang/Object;IILjava/lang/Object;)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_a
    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/lm6;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nf6;Llyiahf/vczjk/hg9;ZLlyiahf/vczjk/qg6;IFLlyiahf/vczjk/uj6;Llyiahf/vczjk/bz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/m4;Llyiahf/vczjk/n4;Llyiahf/vczjk/dv8;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;III)V
    .locals 44

    move-object/from16 v1, p0

    move-object/from16 v3, p1

    move-object/from16 v5, p2

    move/from16 v6, p3

    move-object/from16 v4, p4

    move-object/from16 v0, p5

    move/from16 v2, p6

    move-object/from16 v11, p10

    move-object/from16 v7, p11

    move-object/from16 v8, p12

    move-object/from16 v12, p13

    move/from16 v10, p18

    move/from16 v13, p19

    move/from16 v9, p20

    move-object/from16 v14, p17

    check-cast v14, Llyiahf/vczjk/zf1;

    const v15, 0x43111c3a    # 145.11026f

    invoke-virtual {v14, v15}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v15, v9, 0x1

    const/16 v16, 0x2

    move/from16 p17, v15

    if-eqz p17, :cond_0

    or-int/lit8 v17, v10, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v17, v10, 0x6

    if-nez v17, :cond_2

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v17

    if-eqz v17, :cond_1

    const/16 v17, 0x4

    goto :goto_0

    :cond_1
    move/from16 v17, v16

    :goto_0
    or-int v17, v10, v17

    goto :goto_1

    :cond_2
    move/from16 v17, v10

    :goto_1
    and-int/lit8 v18, v9, 0x2

    const/16 v19, 0x10

    if-eqz v18, :cond_4

    or-int/lit8 v17, v17, 0x30

    :cond_3
    :goto_2
    move/from16 v15, v17

    goto :goto_4

    :cond_4
    and-int/lit8 v18, v10, 0x30

    if-nez v18, :cond_3

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_5

    const/16 v18, 0x20

    goto :goto_3

    :cond_5
    move/from16 v18, v19

    :goto_3
    or-int v17, v17, v18

    goto :goto_2

    :goto_4
    and-int/lit8 v17, v9, 0x4

    const/16 v20, 0x80

    if-eqz v17, :cond_6

    or-int/lit16 v15, v15, 0x180

    goto :goto_6

    :cond_6
    and-int/lit16 v1, v10, 0x180

    if-nez v1, :cond_8

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    const/16 v1, 0x100

    goto :goto_5

    :cond_7
    move/from16 v1, v20

    :goto_5
    or-int/2addr v15, v1

    :cond_8
    :goto_6
    and-int/lit8 v1, v9, 0x8

    const/16 v21, 0x400

    move/from16 v22, v1

    if-eqz v22, :cond_9

    or-int/lit16 v15, v15, 0xc00

    goto :goto_8

    :cond_9
    and-int/lit16 v1, v10, 0xc00

    if-nez v1, :cond_b

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    if-eqz v1, :cond_a

    const/16 v1, 0x800

    goto :goto_7

    :cond_a
    move/from16 v1, v21

    :goto_7
    or-int/2addr v15, v1

    :cond_b
    :goto_8
    and-int/lit8 v1, v9, 0x10

    const/16 v23, 0x2000

    move/from16 v24, v1

    if-eqz v24, :cond_c

    or-int/lit16 v15, v15, 0x6000

    goto :goto_a

    :cond_c
    and-int/lit16 v1, v10, 0x6000

    if-nez v1, :cond_e

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_d

    const/16 v1, 0x4000

    goto :goto_9

    :cond_d
    move/from16 v1, v23

    :goto_9
    or-int/2addr v15, v1

    :cond_e
    :goto_a
    and-int/lit8 v1, v9, 0x20

    const/high16 v25, 0x10000

    move/from16 v26, v1

    const/high16 v27, 0x30000

    if-eqz v26, :cond_f

    or-int v15, v15, v27

    goto :goto_c

    :cond_f
    and-int v26, v10, v27

    if-nez v26, :cond_11

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v26

    if-eqz v26, :cond_10

    const/high16 v26, 0x20000

    goto :goto_b

    :cond_10
    move/from16 v26, v25

    :goto_b
    or-int v15, v15, v26

    :cond_11
    :goto_c
    and-int/lit8 v26, v9, 0x40

    const/high16 v28, 0x180000

    if-eqz v26, :cond_12

    or-int v15, v15, v28

    goto :goto_e

    :cond_12
    and-int v26, v10, v28

    if-nez v26, :cond_14

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v26

    if-eqz v26, :cond_13

    const/high16 v26, 0x100000

    goto :goto_d

    :cond_13
    const/high16 v26, 0x80000

    :goto_d
    or-int v15, v15, v26

    :cond_14
    :goto_e
    and-int/lit16 v1, v9, 0x80

    const/high16 v29, 0xc00000

    if-eqz v1, :cond_16

    or-int v15, v15, v29

    :cond_15
    move-object/from16 v1, p7

    goto :goto_10

    :cond_16
    and-int v1, v10, v29

    if-nez v1, :cond_15

    move-object/from16 v1, p7

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v30

    if-eqz v30, :cond_17

    const/high16 v30, 0x800000

    goto :goto_f

    :cond_17
    const/high16 v30, 0x400000

    :goto_f
    or-int v15, v15, v30

    :goto_10
    and-int/lit16 v1, v9, 0x100

    const/high16 v30, 0x6000000

    if-eqz v1, :cond_19

    or-int v15, v15, v30

    :cond_18
    move/from16 v31, v1

    move/from16 v1, p8

    goto :goto_12

    :cond_19
    and-int v31, v10, v30

    if-nez v31, :cond_18

    move/from16 v31, v1

    move/from16 v1, p8

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v32

    if-eqz v32, :cond_1a

    const/high16 v32, 0x4000000

    goto :goto_11

    :cond_1a
    const/high16 v32, 0x2000000

    :goto_11
    or-int v15, v15, v32

    :goto_12
    and-int/lit16 v1, v9, 0x200

    const/high16 v32, 0x30000000

    if-eqz v1, :cond_1b

    or-int v15, v15, v32

    move/from16 v33, v1

    move/from16 v34, v15

    move/from16 v1, p9

    goto :goto_15

    :cond_1b
    and-int v33, v10, v32

    if-nez v33, :cond_1d

    move/from16 v33, v1

    move/from16 v1, p9

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v34

    if-eqz v34, :cond_1c

    const/high16 v34, 0x20000000

    goto :goto_13

    :cond_1c
    const/high16 v34, 0x10000000

    :goto_13
    or-int v15, v15, v34

    :goto_14
    move/from16 v34, v15

    goto :goto_15

    :cond_1d
    move/from16 v33, v1

    move/from16 v1, p9

    goto :goto_14

    :goto_15
    and-int/lit16 v15, v9, 0x400

    if-eqz v15, :cond_1e

    or-int/lit8 v15, v13, 0x6

    goto :goto_16

    :cond_1e
    and-int/lit8 v15, v13, 0x6

    if-nez v15, :cond_20

    invoke-virtual {v14, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_1f

    const/16 v16, 0x4

    :cond_1f
    or-int v15, v13, v16

    goto :goto_16

    :cond_20
    move v15, v13

    :goto_16
    and-int/lit16 v1, v9, 0x800

    if-eqz v1, :cond_21

    or-int/lit8 v15, v15, 0x30

    goto :goto_17

    :cond_21
    and-int/lit8 v1, v13, 0x30

    if-nez v1, :cond_23

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_22

    const/16 v19, 0x20

    :cond_22
    or-int v15, v15, v19

    :cond_23
    :goto_17
    and-int/lit16 v1, v9, 0x1000

    if-eqz v1, :cond_24

    or-int/lit16 v15, v15, 0x180

    goto :goto_18

    :cond_24
    and-int/lit16 v1, v13, 0x180

    if-nez v1, :cond_26

    invoke-virtual {v14, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_25

    const/16 v20, 0x100

    :cond_25
    or-int v15, v15, v20

    :cond_26
    :goto_18
    and-int/lit16 v1, v9, 0x2000

    if-eqz v1, :cond_27

    or-int/lit16 v15, v15, 0xc00

    goto :goto_19

    :cond_27
    and-int/lit16 v1, v13, 0xc00

    if-nez v1, :cond_29

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_28

    const/16 v21, 0x800

    :cond_28
    or-int v15, v15, v21

    :cond_29
    :goto_19
    and-int/lit16 v1, v9, 0x4000

    if-eqz v1, :cond_2b

    or-int/lit16 v15, v15, 0x6000

    :cond_2a
    move-object/from16 v1, p14

    goto :goto_1a

    :cond_2b
    and-int/lit16 v1, v13, 0x6000

    if-nez v1, :cond_2a

    move-object/from16 v1, p14

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_2c

    const/16 v23, 0x4000

    :cond_2c
    or-int v15, v15, v23

    :goto_1a
    const v16, 0x8000

    and-int v16, v9, v16

    if-eqz v16, :cond_2d

    or-int v15, v15, v27

    move-object/from16 v2, p15

    goto :goto_1c

    :cond_2d
    and-int v16, v13, v27

    move-object/from16 v2, p15

    if-nez v16, :cond_2f

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_2e

    const/high16 v16, 0x20000

    goto :goto_1b

    :cond_2e
    move/from16 v16, v25

    :goto_1b
    or-int v15, v15, v16

    :cond_2f
    :goto_1c
    and-int v16, v9, v25

    if-eqz v16, :cond_30

    or-int v15, v15, v28

    move-object/from16 v7, p16

    goto :goto_1e

    :cond_30
    and-int v16, v13, v28

    move-object/from16 v7, p16

    if-nez v16, :cond_32

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_31

    const/high16 v16, 0x100000

    goto :goto_1d

    :cond_31
    const/high16 v16, 0x80000

    :goto_1d
    or-int v15, v15, v16

    :cond_32
    :goto_1e
    const v16, 0x12492493

    and-int v9, v34, v16

    const/16 v16, 0x1

    const v10, 0x12492492

    const/4 v0, 0x0

    if-ne v9, v10, :cond_34

    const v9, 0x92493

    and-int/2addr v9, v15

    const v10, 0x92492

    if-eq v9, v10, :cond_33

    goto :goto_1f

    :cond_33
    move v9, v0

    goto :goto_20

    :cond_34
    :goto_1f
    move/from16 v9, v16

    :goto_20
    and-int/lit8 v10, v34, 0x1

    invoke-virtual {v14, v10, v9}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v9

    if-eqz v9, :cond_7c

    if-eqz v31, :cond_35

    move v13, v0

    goto :goto_21

    :cond_35
    move/from16 v13, p8

    :goto_21
    if-eqz v33, :cond_36

    int-to-float v9, v0

    goto :goto_22

    :cond_36
    move/from16 v9, p9

    :goto_22
    if-ltz v13, :cond_37

    goto :goto_23

    :cond_37
    new-instance v10, Ljava/lang/StringBuilder;

    const-string v0, "beyondViewportPageCount should be greater than or equal to 0, you selected "

    invoke-direct {v10, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v10, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_23
    and-int/lit8 v0, v34, 0x70

    const/16 v10, 0x20

    if-ne v0, v10, :cond_38

    move/from16 p8, v16

    goto :goto_24

    :cond_38
    const/16 p8, 0x0

    :goto_24
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    move/from16 v20, v13

    sget-object v13, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p8, :cond_39

    if-ne v10, v13, :cond_3a

    :cond_39
    new-instance v10, Llyiahf/vczjk/zt4;

    invoke-direct {v10, v3}, Llyiahf/vczjk/zt4;-><init>(Llyiahf/vczjk/lm6;)V

    invoke-virtual {v14, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3a
    check-cast v10, Llyiahf/vczjk/le3;

    shr-int/lit8 v21, v34, 0x3

    and-int/lit8 v23, v21, 0xe

    shr-int/lit8 v25, v15, 0xf

    and-int/lit8 v31, v25, 0x70

    or-int v31, v23, v31

    and-int/lit16 v2, v15, 0x380

    or-int v2, v31, v2

    move/from16 p8, v2

    invoke-static {v7, v14}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v2

    invoke-static {v8, v14}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v7

    and-int/lit8 v31, p8, 0xe

    xor-int/lit8 v8, v31, 0x6

    move/from16 v31, v15

    const/4 v15, 0x4

    if-le v8, v15, :cond_3b

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_3c

    :cond_3b
    and-int/lit8 v8, p8, 0x6

    if-ne v8, v15, :cond_3d

    :cond_3c
    move/from16 v8, v16

    goto :goto_25

    :cond_3d
    const/4 v8, 0x0

    :goto_25
    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    or-int/2addr v8, v15

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    or-int/2addr v8, v15

    invoke-virtual {v14, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    or-int/2addr v8, v15

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    if-nez v8, :cond_3e

    if-ne v15, v13, :cond_3f

    :cond_3e
    sget-object v8, Llyiahf/vczjk/pp3;->OooOo00:Llyiahf/vczjk/pp3;

    new-instance v15, Llyiahf/vczjk/cu4;

    invoke-direct {v15, v2, v7, v10}, Llyiahf/vczjk/cu4;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/le3;)V

    invoke-static {v15, v8}, Landroidx/compose/runtime/OooO0o;->OooO0o0(Llyiahf/vczjk/le3;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/w62;

    move-result-object v2

    new-instance v7, Llyiahf/vczjk/du4;

    invoke-direct {v7, v2, v3}, Llyiahf/vczjk/du4;-><init>(Llyiahf/vczjk/w62;Llyiahf/vczjk/lm6;)V

    invoke-static {v7, v8}, Landroidx/compose/runtime/OooO0o;->OooO0o0(Llyiahf/vczjk/le3;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/w62;

    move-result-object v39

    new-instance v35, Llyiahf/vczjk/n83;

    const-string v41, "getValue()Ljava/lang/Object;"

    const/16 v36, 0x0

    const-class v38, Llyiahf/vczjk/p29;

    const-string v40, "value"

    const/16 v37, 0x2

    invoke-direct/range {v35 .. v41}, Llyiahf/vczjk/n83;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    move-object/from16 v15, v35

    invoke-virtual {v14, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3f
    move-object v2, v15

    check-cast v2, Llyiahf/vczjk/hh4;

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v13, :cond_40

    invoke-static {v14}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v7

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_40
    move-object v15, v7

    check-cast v15, Llyiahf/vczjk/xr1;

    const/16 v10, 0x20

    if-ne v0, v10, :cond_41

    move/from16 v7, v16

    goto :goto_26

    :cond_41
    const/4 v7, 0x0

    :goto_26
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_42

    if-ne v8, v13, :cond_43

    :cond_42
    new-instance v8, Llyiahf/vczjk/yt4;

    invoke-direct {v8, v3}, Llyiahf/vczjk/yt4;-><init>(Llyiahf/vczjk/lm6;)V

    invoke-virtual {v14, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_43
    move-object v10, v8

    check-cast v10, Llyiahf/vczjk/le3;

    const v7, 0xfff0

    and-int v7, v34, v7

    shr-int/lit8 v8, v34, 0x9

    const/high16 v33, 0x70000

    and-int v35, v8, v33

    or-int v7, v7, v35

    const/high16 v35, 0x380000

    and-int v8, v8, v35

    or-int/2addr v7, v8

    shl-int/lit8 v8, v31, 0x15

    const/high16 v35, 0x1c00000

    and-int v8, v8, v35

    or-int/2addr v7, v8

    shl-int/lit8 v8, v31, 0xf

    const/high16 v31, 0xe000000

    and-int v31, v8, v31

    or-int v7, v7, v31

    const/high16 v31, 0x70000000

    and-int v8, v8, v31

    or-int/2addr v7, v8

    and-int/lit8 v8, v7, 0x70

    xor-int/lit8 v8, v8, 0x30

    move-object/from16 p8, v2

    const/16 v2, 0x20

    if-le v8, v2, :cond_44

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_45

    :cond_44
    and-int/lit8 v8, v7, 0x30

    if-ne v8, v2, :cond_46

    :cond_45
    move/from16 v8, v16

    goto :goto_27

    :cond_46
    const/4 v8, 0x0

    :goto_27
    and-int/lit16 v2, v7, 0x380

    xor-int/lit16 v2, v2, 0x180

    const/16 v3, 0x100

    if-le v2, v3, :cond_47

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_48

    :cond_47
    and-int/lit16 v2, v7, 0x180

    if-ne v2, v3, :cond_49

    :cond_48
    move/from16 v2, v16

    goto :goto_28

    :cond_49
    const/4 v2, 0x0

    :goto_28
    or-int/2addr v2, v8

    and-int/lit16 v3, v7, 0x1c00

    xor-int/lit16 v3, v3, 0xc00

    const/16 v8, 0x800

    if-le v3, v8, :cond_4a

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v3

    if-nez v3, :cond_4b

    :cond_4a
    and-int/lit16 v3, v7, 0xc00

    if-ne v3, v8, :cond_4c

    :cond_4b
    move/from16 v3, v16

    goto :goto_29

    :cond_4c
    const/4 v3, 0x0

    :goto_29
    or-int/2addr v2, v3

    const v3, 0xe000

    and-int/2addr v3, v7

    xor-int/lit16 v3, v3, 0x6000

    const/16 v8, 0x4000

    if-le v3, v8, :cond_4d

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_4e

    :cond_4d
    and-int/lit16 v3, v7, 0x6000

    if-ne v3, v8, :cond_4f

    :cond_4e
    move/from16 v3, v16

    goto :goto_2a

    :cond_4f
    const/4 v3, 0x0

    :goto_2a
    or-int/2addr v2, v3

    const/high16 v3, 0xe000000

    and-int/2addr v3, v7

    xor-int v3, v3, v30

    const/high16 v8, 0x4000000

    if-le v3, v8, :cond_50

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_51

    :cond_50
    and-int v3, v7, v30

    if-ne v3, v8, :cond_52

    :cond_51
    move/from16 v3, v16

    goto :goto_2b

    :cond_52
    const/4 v3, 0x0

    :goto_2b
    or-int/2addr v2, v3

    const/high16 v3, 0x70000000

    and-int/2addr v3, v7

    xor-int v3, v3, v32

    const/high16 v8, 0x20000000

    if-le v3, v8, :cond_53

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_54

    :cond_53
    and-int v3, v7, v32

    if-ne v3, v8, :cond_55

    :cond_54
    move/from16 v3, v16

    goto :goto_2c

    :cond_55
    const/4 v3, 0x0

    :goto_2c
    or-int/2addr v2, v3

    const/high16 v3, 0x380000

    and-int/2addr v3, v7

    xor-int v3, v3, v28

    const/high16 v8, 0x100000

    if-le v3, v8, :cond_56

    invoke-virtual {v14, v9}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v3

    if-nez v3, :cond_57

    :cond_56
    and-int v3, v7, v28

    if-ne v3, v8, :cond_58

    :cond_57
    move/from16 v3, v16

    goto :goto_2d

    :cond_58
    const/4 v3, 0x0

    :goto_2d
    or-int/2addr v2, v3

    const/high16 v3, 0x1c00000

    and-int/2addr v3, v7

    xor-int v3, v3, v29

    const/high16 v8, 0x800000

    if-le v3, v8, :cond_59

    invoke-virtual {v14, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_5a

    :cond_59
    and-int v3, v7, v29

    if-ne v3, v8, :cond_5b

    :cond_5a
    move/from16 v3, v16

    goto :goto_2e

    :cond_5b
    const/4 v3, 0x0

    :goto_2e
    or-int/2addr v2, v3

    and-int/lit8 v3, v25, 0xe

    xor-int/lit8 v3, v3, 0x6

    const/4 v8, 0x4

    if-le v3, v8, :cond_5c

    move-object/from16 v3, p15

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v17

    if-nez v17, :cond_5d

    goto :goto_2f

    :cond_5c
    move-object/from16 v3, p15

    :goto_2f
    and-int/lit8 v1, v25, 0x6

    if-ne v1, v8, :cond_5e

    :cond_5d
    move/from16 v1, v16

    goto :goto_30

    :cond_5e
    const/4 v1, 0x0

    :goto_30
    or-int/2addr v1, v2

    invoke-virtual {v14, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    and-int v2, v7, v33

    xor-int v2, v2, v27

    const/high16 v8, 0x20000

    if-le v2, v8, :cond_5f

    move/from16 v2, v20

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v17

    if-nez v17, :cond_60

    goto :goto_31

    :cond_5f
    move/from16 v2, v20

    :goto_31
    and-int v7, v7, v27

    if-ne v7, v8, :cond_61

    :cond_60
    move/from16 v7, v16

    goto :goto_32

    :cond_61
    const/4 v7, 0x0

    :goto_32
    or-int/2addr v1, v7

    invoke-virtual {v14, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    or-int/2addr v1, v7

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v1, :cond_62

    if-ne v7, v13, :cond_63

    :cond_62
    move/from16 v20, v2

    goto :goto_33

    :cond_63
    move-object/from16 v8, p1

    move-object/from16 v3, p8

    move/from16 p8, v0

    move v12, v9

    move-object/from16 v42, v13

    move-object v1, v14

    const/4 v0, 0x4

    move v13, v2

    goto :goto_34

    :goto_33
    new-instance v2, Llyiahf/vczjk/nl6;

    move v7, v9

    move-object v8, v11

    move-object/from16 v42, v13

    move-object v1, v14

    move/from16 v13, v20

    move-object/from16 v9, p8

    move-object/from16 v11, p14

    move/from16 p8, v0

    move-object v14, v3

    const/4 v0, 0x4

    move-object/from16 v3, p1

    invoke-direct/range {v2 .. v15}, Llyiahf/vczjk/nl6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/nf6;Llyiahf/vczjk/bi6;ZFLlyiahf/vczjk/uj6;Llyiahf/vczjk/hh4;Llyiahf/vczjk/le3;Llyiahf/vczjk/n4;Llyiahf/vczjk/m4;ILlyiahf/vczjk/dv8;Llyiahf/vczjk/xr1;)V

    move-object v8, v3

    move v12, v7

    move-object v3, v9

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v7, v2

    :goto_34
    move-object v14, v7

    check-cast v14, Llyiahf/vczjk/ze3;

    sget-object v9, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v4, v9, :cond_64

    move/from16 v2, v16

    goto :goto_35

    :cond_64
    const/4 v2, 0x0

    :goto_35
    xor-int/lit8 v5, v23, 0x6

    if-le v5, v0, :cond_65

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_66

    :cond_65
    and-int/lit8 v5, v21, 0x6

    if-ne v5, v0, :cond_67

    :cond_66
    move/from16 v5, v16

    goto :goto_36

    :cond_67
    const/4 v5, 0x0

    :goto_36
    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v7

    or-int/2addr v5, v7

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v5, :cond_68

    move-object/from16 v5, v42

    if-ne v7, v5, :cond_69

    goto :goto_37

    :cond_68
    move-object/from16 v5, v42

    :goto_37
    new-instance v7, Llyiahf/vczjk/su4;

    const/4 v10, 0x0

    invoke-direct {v7, v8, v2, v10}, Llyiahf/vczjk/su4;-><init>(Llyiahf/vczjk/sa8;ZI)V

    invoke-virtual {v1, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_69
    check-cast v7, Llyiahf/vczjk/ru4;

    move/from16 v2, p8

    const/16 v10, 0x20

    if-ne v2, v10, :cond_6a

    move/from16 v11, v16

    goto :goto_38

    :cond_6a
    const/4 v11, 0x0

    :goto_38
    and-int v0, v34, v33

    const/high16 v10, 0x20000

    if-ne v0, v10, :cond_6b

    move/from16 v0, v16

    goto :goto_39

    :cond_6b
    const/4 v0, 0x0

    :goto_39
    or-int/2addr v0, v11

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v0, :cond_6d

    if-ne v10, v5, :cond_6c

    goto :goto_3a

    :cond_6c
    move-object/from16 v0, p5

    goto :goto_3b

    :cond_6d
    :goto_3a
    new-instance v10, Llyiahf/vczjk/wm6;

    move-object/from16 v0, p5

    invoke-direct {v10, v0, v8}, Llyiahf/vczjk/wm6;-><init>(Llyiahf/vczjk/hg9;Llyiahf/vczjk/lm6;)V

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_3b
    check-cast v10, Llyiahf/vczjk/wm6;

    sget-object v11, Llyiahf/vczjk/ii0;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/gi0;

    const/16 v0, 0x20

    if-ne v2, v0, :cond_6e

    move/from16 v0, v16

    goto :goto_3c

    :cond_6e
    const/4 v0, 0x0

    :goto_3c
    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v0, v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_6f

    if-ne v2, v5, :cond_70

    :cond_6f
    new-instance v2, Llyiahf/vczjk/rk6;

    invoke-direct {v2, v8, v11}, Llyiahf/vczjk/rk6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/gi0;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_70
    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/rk6;

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz p6, :cond_79

    const v2, 0x735b3d0d

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    shr-int/lit8 v2, v34, 0x15

    and-int/lit8 v2, v2, 0x70

    or-int v2, v23, v2

    and-int/lit8 v17, v2, 0xe

    move/from16 p8, v2

    xor-int/lit8 v2, v17, 0x6

    move-object/from16 p9, v3

    const/4 v3, 0x4

    if-le v2, v3, :cond_71

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_72

    :cond_71
    and-int/lit8 v2, p8, 0x6

    if-ne v2, v3, :cond_73

    :cond_72
    move/from16 v2, v16

    goto :goto_3d

    :cond_73
    const/4 v2, 0x0

    :goto_3d
    and-int/lit8 v3, p8, 0x70

    xor-int/lit8 v3, v3, 0x30

    move/from16 p17, v2

    const/16 v2, 0x20

    if-le v3, v2, :cond_74

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v3

    if-nez v3, :cond_75

    :cond_74
    and-int/lit8 v3, p8, 0x30

    if-ne v3, v2, :cond_76

    :cond_75
    move/from16 v2, v16

    goto :goto_3e

    :cond_76
    const/4 v2, 0x0

    :goto_3e
    or-int v2, p17, v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_77

    if-ne v3, v5, :cond_78

    :cond_77
    new-instance v3, Llyiahf/vczjk/qk6;

    invoke-direct {v3, v8, v13}, Llyiahf/vczjk/qk6;-><init>(Llyiahf/vczjk/lm6;I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_78
    check-cast v3, Llyiahf/vczjk/qk6;

    iget-object v2, v8, Llyiahf/vczjk/lm6;->OooOo0O:Llyiahf/vczjk/vz5;

    invoke-static {v3, v2, v6, v4}, Landroidx/compose/foundation/lazy/layout/OooO0O0;->OooO0Oo(Llyiahf/vczjk/os4;Llyiahf/vczjk/vz5;ZLlyiahf/vczjk/nf6;)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3f

    :cond_79
    move-object/from16 p9, v3

    const/4 v3, 0x0

    const v2, 0x7361c824

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v2, v0

    :goto_3f
    iget-object v5, v8, Llyiahf/vczjk/lm6;->OooOoO0:Llyiahf/vczjk/ar4;

    move-object/from16 v17, v1

    move-object/from16 v1, p0

    invoke-interface {v1, v5}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    iget-object v3, v8, Llyiahf/vczjk/lm6;->OooOo0o:Llyiahf/vczjk/g20;

    invoke-interface {v5, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    move-object v1, v2

    move-object v2, v3

    move-object v5, v4

    move-object v4, v7

    const/16 v19, 0x0

    move-object/from16 v3, p9

    move v7, v6

    move/from16 v6, p6

    invoke-static/range {v2 .. v7}, Landroidx/compose/foundation/lazy/layout/OooO0O0;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/hh4;Llyiahf/vczjk/ru4;Llyiahf/vczjk/nf6;ZZ)Llyiahf/vczjk/kl5;

    move-result-object v2

    move-object/from16 v18, v3

    move-object v4, v5

    if-ne v4, v9, :cond_7a

    move/from16 v3, v16

    goto :goto_40

    :cond_7a
    move/from16 v3, v19

    :goto_40
    if-eqz p6, :cond_7b

    new-instance v5, Llyiahf/vczjk/zk6;

    invoke-direct {v5, v3, v8, v15}, Llyiahf/vczjk/zk6;-><init>(ZLlyiahf/vczjk/lm6;Llyiahf/vczjk/xr1;)V

    const/4 v3, 0x0

    invoke-static {v0, v3, v5}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-interface {v2, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    goto :goto_41

    :cond_7b
    invoke-interface {v2, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    :goto_41
    invoke-interface {v2, v1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v9, 0x0

    move-object v3, v8

    iget-object v8, v3, Llyiahf/vczjk/lm6;->OooOOo:Llyiahf/vczjk/sr5;

    move/from16 v6, p3

    move/from16 v5, p6

    move-object v7, v10

    move-object/from16 v10, p7

    invoke-static/range {v2 .. v11}, Landroidx/compose/foundation/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;Llyiahf/vczjk/sa8;Llyiahf/vczjk/nf6;ZZLlyiahf/vczjk/o23;Llyiahf/vczjk/sr5;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/rk6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    move-object v9, v3

    new-instance v2, Llyiahf/vczjk/o0000O0;

    const/4 v3, 0x3

    invoke-direct {v2, v9, v3}, Llyiahf/vczjk/o0000O0;-><init>(Ljava/lang/Object;I)V

    invoke-static {v0, v9, v2}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-interface {v1, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    const/4 v1, 0x0

    move-object/from16 v10, p11

    invoke-static {v0, v10, v1}, Landroidx/compose/ui/input/nestedscroll/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/4 v8, 0x0

    iget-object v4, v9, Llyiahf/vczjk/lm6;->OooOo0:Llyiahf/vczjk/ku4;

    const/4 v7, 0x0

    move-object v5, v14

    move-object/from16 v6, v17

    move-object/from16 v2, v18

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/m6a;->OooO0oO(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/ku4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object v1, v6

    move v10, v12

    goto :goto_42

    :cond_7c
    move-object/from16 v10, p11

    move-object v9, v3

    move-object v1, v14

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move/from16 v13, p8

    move/from16 v10, p9

    :goto_42
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_7d

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/xt4;

    move-object/from16 v3, p2

    move/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v11, p10

    move-object/from16 v12, p11

    move-object/from16 v14, p13

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move-object/from16 v17, p16

    move/from16 v18, p18

    move/from16 v19, p19

    move/from16 v20, p20

    move-object/from16 v43, v1

    move-object v2, v9

    move v9, v13

    move-object/from16 v1, p0

    move-object/from16 v13, p12

    invoke-direct/range {v0 .. v20}, Llyiahf/vczjk/xt4;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/lm6;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nf6;Llyiahf/vczjk/hg9;ZLlyiahf/vczjk/qg6;IFLlyiahf/vczjk/uj6;Llyiahf/vczjk/bz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/m4;Llyiahf/vczjk/n4;Llyiahf/vczjk/dv8;Llyiahf/vczjk/df3;III)V

    move-object/from16 v1, v43

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7d
    return-void
.end method

.method public static final OooOO0(Llyiahf/vczjk/v86;ZLlyiahf/vczjk/rr7;ZJFLlyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;II)V
    .locals 19

    move-object/from16 v6, p0

    move/from16 v7, p1

    move-object/from16 v8, p2

    move/from16 v9, p3

    move-object/from16 v10, p7

    move/from16 v11, p9

    const/4 v0, 0x2

    const/16 v1, 0x10

    move-object/from16 v12, p8

    check-cast v12, Llyiahf/vczjk/zf1;

    const v2, -0x1bcadee8

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const/4 v2, 0x1

    and-int/lit8 v3, p10, 0x1

    const/4 v4, 0x4

    if-eqz v3, :cond_0

    or-int/lit8 v3, v11, 0x6

    goto :goto_2

    :cond_0
    and-int/lit8 v3, v11, 0x6

    if-nez v3, :cond_3

    and-int/lit8 v3, v11, 0x8

    if-nez v3, :cond_1

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    goto :goto_0

    :cond_1
    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    :goto_0
    if-eqz v3, :cond_2

    move v3, v4

    goto :goto_1

    :cond_2
    move v3, v0

    :goto_1
    or-int/2addr v3, v11

    goto :goto_2

    :cond_3
    move v3, v11

    :goto_2
    and-int/lit8 v0, p10, 0x2

    const/16 v5, 0x20

    if-eqz v0, :cond_4

    or-int/lit8 v3, v3, 0x30

    goto :goto_4

    :cond_4
    and-int/lit8 v0, v11, 0x30

    if-nez v0, :cond_6

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    if-eqz v0, :cond_5

    move v0, v5

    goto :goto_3

    :cond_5
    move v0, v1

    :goto_3
    or-int/2addr v3, v0

    :cond_6
    :goto_4
    and-int/lit8 v0, p10, 0x4

    if-eqz v0, :cond_7

    or-int/lit16 v3, v3, 0x180

    goto :goto_6

    :cond_7
    and-int/lit16 v0, v11, 0x180

    if-nez v0, :cond_9

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_8

    const/16 v0, 0x100

    goto :goto_5

    :cond_8
    const/16 v0, 0x80

    :goto_5
    or-int/2addr v3, v0

    :cond_9
    :goto_6
    and-int/lit8 v0, p10, 0x8

    if-eqz v0, :cond_a

    or-int/lit16 v3, v3, 0xc00

    goto :goto_8

    :cond_a
    and-int/lit16 v0, v11, 0xc00

    if-nez v0, :cond_c

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    if-eqz v0, :cond_b

    const/16 v0, 0x800

    goto :goto_7

    :cond_b
    const/16 v0, 0x400

    :goto_7
    or-int/2addr v3, v0

    :cond_c
    :goto_8
    and-int/lit16 v0, v11, 0x6000

    if-nez v0, :cond_e

    and-int/lit8 v0, p10, 0x10

    move-wide/from16 v13, p4

    if-nez v0, :cond_d

    invoke-virtual {v12, v13, v14}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v0

    if-eqz v0, :cond_d

    const/16 v0, 0x4000

    goto :goto_9

    :cond_d
    const/16 v0, 0x2000

    :goto_9
    or-int/2addr v3, v0

    goto :goto_a

    :cond_e
    move-wide/from16 v13, p4

    :goto_a
    and-int/lit8 v0, p10, 0x40

    const/high16 v15, 0x180000

    if-eqz v0, :cond_f

    or-int/2addr v3, v15

    goto :goto_c

    :cond_f
    and-int v0, v11, v15

    if-nez v0, :cond_11

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_10

    const/high16 v0, 0x100000

    goto :goto_b

    :cond_10
    const/high16 v0, 0x80000

    :goto_b
    or-int/2addr v3, v0

    :cond_11
    :goto_c
    const v0, 0x82493

    and-int/2addr v0, v3

    const v15, 0x82492

    move/from16 v16, v1

    if-eq v0, v15, :cond_12

    move v0, v2

    goto :goto_d

    :cond_12
    const/4 v0, 0x0

    :goto_d
    and-int/lit8 v15, v3, 0x1

    invoke-virtual {v12, v15, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_23

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v0, v11, 0x1

    const v15, -0xe001

    if-eqz v0, :cond_14

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_13

    goto :goto_e

    :cond_13
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v0, p10, 0x10

    if-eqz v0, :cond_15

    and-int/2addr v3, v15

    goto :goto_f

    :cond_14
    :goto_e
    and-int/lit8 v0, p10, 0x10

    if-eqz v0, :cond_15

    and-int/2addr v3, v15

    const-wide v13, 0x7fc000007fc00000L    # 2.247117487993712E307

    :cond_15
    :goto_f
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOo0()V

    if-eqz v7, :cond_17

    sget v0, Llyiahf/vczjk/zd8;->OooO00o:F

    sget-object v0, Llyiahf/vczjk/rr7;->OooOOO0:Llyiahf/vczjk/rr7;

    if-ne v8, v0, :cond_16

    if-eqz v9, :cond_1b

    :cond_16
    sget-object v0, Llyiahf/vczjk/rr7;->OooOOO:Llyiahf/vczjk/rr7;

    if-ne v8, v0, :cond_1c

    if-eqz v9, :cond_1c

    goto :goto_11

    :cond_17
    sget v0, Llyiahf/vczjk/zd8;->OooO00o:F

    sget-object v0, Llyiahf/vczjk/rr7;->OooOOO0:Llyiahf/vczjk/rr7;

    if-ne v8, v0, :cond_18

    if-eqz v9, :cond_19

    :cond_18
    sget-object v0, Llyiahf/vczjk/rr7;->OooOOO:Llyiahf/vczjk/rr7;

    if-ne v8, v0, :cond_1a

    if-eqz v9, :cond_1a

    :cond_19
    move v0, v2

    goto :goto_10

    :cond_1a
    const/4 v0, 0x0

    :goto_10
    if-nez v0, :cond_1c

    :cond_1b
    :goto_11
    move v0, v2

    goto :goto_12

    :cond_1c
    const/4 v0, 0x0

    :goto_12
    if-eqz v0, :cond_1d

    sget-object v15, Llyiahf/vczjk/ng0;->OooO0O0:Llyiahf/vczjk/rb0;

    goto :goto_13

    :cond_1d
    sget-object v15, Llyiahf/vczjk/ng0;->OooO00o:Llyiahf/vczjk/rb0;

    :goto_13
    and-int/lit8 v1, v3, 0xe

    if-eq v1, v4, :cond_1f

    and-int/lit8 v4, v3, 0x8

    if-eqz v4, :cond_1e

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1e

    goto :goto_14

    :cond_1e
    const/4 v4, 0x0

    goto :goto_15

    :cond_1f
    :goto_14
    move v4, v2

    :goto_15
    and-int/lit8 v3, v3, 0x70

    if-ne v3, v5, :cond_20

    goto :goto_16

    :cond_20
    const/4 v2, 0x0

    :goto_16
    or-int/2addr v2, v4

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_21

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v2, :cond_22

    :cond_21
    new-instance v3, Llyiahf/vczjk/dg;

    invoke-direct {v3, v6, v7, v0}, Llyiahf/vczjk/dg;-><init>(Llyiahf/vczjk/v86;ZZ)V

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_22
    check-cast v3, Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-static {v10, v2, v3}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v2, Llyiahf/vczjk/ch1;->OooOOoo:Llyiahf/vczjk/l39;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gga;

    move v4, v0

    new-instance v0, Llyiahf/vczjk/bg;

    move-wide/from16 v17, v13

    move v13, v1

    move-object v1, v2

    move-wide/from16 v2, v17

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/bg;-><init>(Llyiahf/vczjk/gga;JZLlyiahf/vczjk/kl5;Llyiahf/vczjk/v86;)V

    const v1, 0x515e2041

    invoke-static {v1, v0, v12}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    or-int/lit16 v1, v13, 0x180

    invoke-static {v6, v15, v0, v12, v1}, Llyiahf/vczjk/nqa;->OooO0O0(Llyiahf/vczjk/v86;Llyiahf/vczjk/o4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    move-wide v13, v2

    goto :goto_17

    :cond_23
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_17
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v12

    if-eqz v12, :cond_24

    new-instance v0, Llyiahf/vczjk/cg;

    move-object v1, v6

    move v2, v7

    move-object v3, v8

    move v4, v9

    move-object v8, v10

    move v9, v11

    move-wide v5, v13

    move/from16 v7, p6

    move/from16 v10, p10

    invoke-direct/range {v0 .. v10}, Llyiahf/vczjk/cg;-><init>(Llyiahf/vczjk/v86;ZLlyiahf/vczjk/rr7;ZJFLlyiahf/vczjk/kl5;II)V

    iput-object v0, v12, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_24
    return-void
.end method

.method public static final OooOO0O(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/rf1;I)V
    .locals 4

    check-cast p3, Llyiahf/vczjk/zf1;

    const v0, 0x7ddd909a

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p4, 0x6

    if-nez v0, :cond_1

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    goto :goto_1

    :cond_1
    move v0, p4

    :goto_1
    and-int/lit8 v1, p4, 0x30

    if-nez v1, :cond_3

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x20

    goto :goto_2

    :cond_2
    const/16 v1, 0x10

    :goto_2
    or-int/2addr v0, v1

    :cond_3
    and-int/lit16 v1, p4, 0x180

    if-nez v1, :cond_5

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x100

    goto :goto_3

    :cond_4
    const/16 v1, 0x80

    :goto_3
    or-int/2addr v0, v1

    :cond_5
    and-int/lit16 v1, v0, 0x93

    const/16 v2, 0x92

    const/4 v3, 0x1

    if-eq v1, v2, :cond_6

    move v1, v3

    goto :goto_4

    :cond_6
    const/4 v1, 0x0

    :goto_4
    and-int/2addr v0, v3

    invoke-virtual {p3, v0, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_7

    sget v0, Llyiahf/vczjk/zd8;->OooO00o:F

    sget v1, Llyiahf/vczjk/zd8;->OooO0O0:F

    invoke-static {p0, v0, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOO0(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hg;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/hg;-><init>(Llyiahf/vczjk/le3;Z)V

    invoke-static {v0, v1}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {p3, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    goto :goto_5

    :cond_7
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p3

    if-eqz p3, :cond_8

    new-instance v0, Llyiahf/vczjk/eg;

    invoke-direct {v0, p0, p1, p2, p4}, Llyiahf/vczjk/eg;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;ZI)V

    iput-object v0, p3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void
.end method

.method public static final OooOO0o(Llyiahf/vczjk/hl5;Llyiahf/vczjk/tv7;JLlyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 18

    move/from16 v7, p7

    move-object/from16 v15, p6

    check-cast v15, Llyiahf/vczjk/zf1;

    const v0, 0x21812ff8

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    or-int/lit16 v0, v7, 0xcb6

    and-int/lit16 v0, v0, 0x2493

    const/16 v1, 0x2492

    if-ne v0, v1, :cond_1

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-wide/from16 v3, p2

    move-object/from16 v5, p4

    goto/16 :goto_3

    :cond_1
    :goto_0
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v0, v7, 0x1

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v2, 0x0

    if-eqz v0, :cond_3

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v0, p0

    move-object/from16 v11, p1

    move-wide/from16 v4, p2

    move-object/from16 v8, p4

    goto :goto_2

    :cond_3
    :goto_1
    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v3, Llyiahf/vczjk/el8;->OooO00o:Llyiahf/vczjk/tv7;

    const/4 v4, 0x0

    const/4 v5, 0x1

    invoke-static {v4, v15, v5}, Llyiahf/vczjk/u34;->OooO0o(FLlyiahf/vczjk/rf1;I)J

    move-result-wide v4

    const v6, 0x6e3c21fe

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v1, :cond_4

    new-instance v6, Llyiahf/vczjk/oOOO0OO0;

    const/16 v8, 0x16

    invoke-direct {v6, v8}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v11, v3

    move-object v8, v6

    :goto_2
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo0()V

    const v3, 0x4c5de2

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v1, :cond_5

    new-instance v3, Llyiahf/vczjk/a5;

    const/16 v1, 0xb

    invoke-direct {v3, v1, v8}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v1, 0x7

    const/4 v6, 0x0

    invoke-static {v0, v2, v6, v3, v1}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-static {v4, v5, v15, v2}, Llyiahf/vczjk/l4a;->OooOO0O(JLlyiahf/vczjk/rf1;I)Llyiahf/vczjk/sq0;

    move-result-object v12

    const/4 v10, 0x0

    const/4 v13, 0x0

    const v16, 0x6000c06

    const/16 v17, 0xe4

    move-object/from16 v14, p5

    invoke-static/range {v8 .. v17}, Llyiahf/vczjk/c6a;->OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/sq0;Llyiahf/vczjk/vq0;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    move-object v1, v0

    move-wide v3, v4

    move-object v5, v8

    move-object v2, v11

    :goto_3
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_6

    new-instance v0, Llyiahf/vczjk/xq0;

    move-object/from16 v6, p5

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/xq0;-><init>(Llyiahf/vczjk/hl5;Llyiahf/vczjk/tv7;JLlyiahf/vczjk/le3;Llyiahf/vczjk/a91;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void
.end method

.method public static final OooOOO(Landroid/view/View;Llyiahf/vczjk/xa;)Llyiahf/vczjk/wj7;
    .locals 5

    sget-object v0, Llyiahf/vczjk/r02;->OooO0oo:[I

    invoke-virtual {p0, v0}, Landroid/view/View;->getLocationInWindow([I)V

    const/4 v1, 0x0

    aget v2, v0, v1

    const/4 v3, 0x1

    aget v4, v0, v3

    invoke-virtual {p1, v0}, Landroid/view/View;->getLocationInWindow([I)V

    aget p1, v0, v1

    aget v0, v0, v3

    sub-int/2addr v2, p1

    int-to-float p1, v2

    sub-int/2addr v4, v0

    int-to-float v0, v4

    new-instance v1, Llyiahf/vczjk/wj7;

    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    move-result v2

    int-to-float v2, v2

    add-float/2addr v2, p1

    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    move-result p0

    int-to-float p0, p0

    add-float/2addr p0, v0

    invoke-direct {v1, p1, v0, v2, p0}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    return-object v1
.end method

.method public static OooOOO0(Landroid/widget/EdgeEffect;FFLlyiahf/vczjk/f62;)F
    .locals 8

    sget v0, Llyiahf/vczjk/mk2;->OooO00o:F

    const v0, 0x43c10b3d

    invoke-interface {p3}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result p3

    mul-float/2addr p3, v0

    const/high16 v0, 0x43200000    # 160.0f

    mul-float/2addr p3, v0

    const v0, 0x3f570a3d    # 0.84f

    mul-float/2addr p3, v0

    float-to-double v0, p3

    const p3, 0x3eb33333    # 0.35f

    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    move-result v2

    mul-float/2addr v2, p3

    float-to-double v2, v2

    sget p3, Llyiahf/vczjk/mk2;->OooO00o:F

    float-to-double v4, p3

    mul-double/2addr v4, v0

    div-double/2addr v2, v4

    invoke-static {v2, v3}, Ljava/lang/Math;->log(D)D

    move-result-wide v0

    sget-wide v2, Llyiahf/vczjk/mk2;->OooO0O0:D

    sget-wide v6, Llyiahf/vczjk/mk2;->OooO0OO:D

    div-double/2addr v2, v6

    mul-double/2addr v2, v0

    invoke-static {v2, v3}, Ljava/lang/Math;->exp(D)D

    move-result-wide v0

    mul-double/2addr v0, v4

    double-to-float p3, v0

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/4 v1, 0x0

    const/16 v2, 0x1f

    if-lt v0, v2, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/yo;->OooO0O0(Landroid/widget/EdgeEffect;)F

    move-result v3

    goto :goto_0

    :cond_0
    move v3, v1

    :goto_0
    mul-float/2addr v3, p2

    cmpg-float p2, p3, v3

    if-gtz p2, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result p2

    if-lt v0, v2, :cond_1

    invoke-virtual {p0, p2}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    return p1

    :cond_1
    invoke-virtual {p0}, Landroid/widget/EdgeEffect;->isFinished()Z

    move-result p3

    if-eqz p3, :cond_2

    invoke-virtual {p0, p2}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    :cond_2
    return p1

    :cond_3
    return v1
.end method

.method public static final OooOOOO(Llyiahf/vczjk/eo1;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/bo1;->OooO00o:Llyiahf/vczjk/bo1;

    iget-object p0, p0, Llyiahf/vczjk/eo1;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast p0, Llyiahf/vczjk/fw8;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public static final OooOOOo(Llyiahf/vczjk/un6;Ljava/util/List;Llyiahf/vczjk/kd;Llyiahf/vczjk/rf1;)V
    .locals 0

    const-string p2, "<this>"

    invoke-static {p0, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "imagePlugins"

    invoke-static {p1, p0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p3, Llyiahf/vczjk/zf1;

    const p0, 0x439a0674

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance p0, Ljava/util/ArrayList;

    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-nez p1, :cond_1

    const/4 p0, 0x0

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-void

    :cond_1
    invoke-static {p0}, Llyiahf/vczjk/q99;->OooO0o0(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    move-result-object p0

    throw p0
.end method

.method public static OooOOo(IJ)J
    .locals 2

    invoke-static {p1, p2}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    and-int/lit8 p0, p0, 0x4

    const/4 v1, 0x0

    if-eqz p0, :cond_0

    invoke-static {p1, p2}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result p0

    goto :goto_0

    :cond_0
    move p0, v1

    :goto_0
    invoke-static {p1, p2}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p1

    invoke-static {v1, v0, p0, p1}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p0

    return-wide p0
.end method

.method public static OooOOo0(JLlyiahf/vczjk/gp4;)J
    .locals 4

    sget-object v0, Llyiahf/vczjk/gp4;->OooOOO0:Llyiahf/vczjk/gp4;

    if-ne p2, v0, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v1

    goto :goto_0

    :cond_0
    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v1

    :goto_0
    if-ne p2, v0, :cond_1

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v2

    goto :goto_1

    :cond_1
    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v2

    :goto_1
    if-ne p2, v0, :cond_2

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v3

    goto :goto_2

    :cond_2
    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v3

    :goto_2
    if-ne p2, v0, :cond_3

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p0

    goto :goto_3

    :cond_3
    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result p0

    :goto_3
    invoke-static {v1, v2, v3, p0}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOOoo(Llyiahf/vczjk/tm0;F)Llyiahf/vczjk/lu3;
    .locals 30

    move-object/from16 v0, p0

    move/from16 v3, p1

    float-to-double v1, v3

    invoke-static {v1, v2}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v1

    double-to-float v1, v1

    float-to-int v1, v1

    mul-int/lit8 v1, v1, 0x2

    sget-object v2, Llyiahf/vczjk/zsa;->OooOO0O:Llyiahf/vczjk/kd;

    sget-object v4, Llyiahf/vczjk/zsa;->OooOO0o:Llyiahf/vczjk/s9;

    sget-object v5, Llyiahf/vczjk/zsa;->OooOOO0:Llyiahf/vczjk/gq0;

    if-eqz v2, :cond_1

    if-eqz v4, :cond_1

    iget-object v6, v2, Llyiahf/vczjk/kd;->OooO00o:Landroid/graphics/Bitmap;

    invoke-virtual {v6}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v7

    if-gt v1, v7, :cond_1

    invoke-virtual {v6}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v6

    if-le v1, v6, :cond_0

    goto :goto_1

    :cond_0
    :goto_0
    move-object v8, v2

    move-object v9, v4

    goto :goto_2

    :cond_1
    :goto_1
    const/4 v2, 0x1

    invoke-static {v1, v1, v2}, Llyiahf/vczjk/os9;->OooOO0(III)Llyiahf/vczjk/kd;

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/zsa;->OooOO0O:Llyiahf/vczjk/kd;

    invoke-static {v2}, Llyiahf/vczjk/e16;->OooO00o(Llyiahf/vczjk/kd;)Llyiahf/vczjk/s9;

    move-result-object v4

    sput-object v4, Llyiahf/vczjk/zsa;->OooOO0o:Llyiahf/vczjk/s9;

    goto :goto_0

    :goto_2
    if-nez v5, :cond_2

    new-instance v5, Llyiahf/vczjk/gq0;

    invoke-direct {v5}, Llyiahf/vczjk/gq0;-><init>()V

    sput-object v5, Llyiahf/vczjk/zsa;->OooOOO0:Llyiahf/vczjk/gq0;

    :cond_2
    move-object v10, v5

    iget-object v1, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v1}, Llyiahf/vczjk/qj0;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v1

    iget-object v2, v8, Llyiahf/vczjk/kd;->OooO00o:Landroid/graphics/Bitmap;

    invoke-virtual {v2}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v4

    int-to-float v4, v4

    invoke-virtual {v2}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v2

    int-to-float v2, v2

    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    int-to-long v4, v4

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v6, v2

    const/16 v2, 0x20

    shl-long/2addr v4, v2

    const-wide v21, 0xffffffffL

    and-long v6, v6, v21

    or-long/2addr v4, v6

    iget-object v6, v10, Llyiahf/vczjk/gq0;->OooOOO0:Llyiahf/vczjk/fq0;

    iget-object v7, v6, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iget-object v11, v6, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    iget-object v12, v6, Llyiahf/vczjk/fq0;->OooO0OO:Llyiahf/vczjk/eq0;

    iget-wide v13, v6, Llyiahf/vczjk/fq0;->OooO0Oo:J

    iput-object v0, v6, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iput-object v1, v6, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    iput-object v9, v6, Llyiahf/vczjk/fq0;->OooO0OO:Llyiahf/vczjk/eq0;

    iput-wide v4, v6, Llyiahf/vczjk/fq0;->OooO0Oo:J

    invoke-virtual {v9}, Llyiahf/vczjk/s9;->OooO0oO()V

    move-object v0, v11

    move-object v1, v12

    sget-wide v11, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-interface {v10}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v15

    const/16 v18, 0x0

    const/16 v19, 0x0

    move-wide v4, v13

    const-wide/16 v13, 0x0

    const/16 v17, 0x0

    const/16 v20, 0x3a

    invoke-static/range {v10 .. v20}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    const-wide v23, 0xff000000L

    invoke-static/range {v23 .. v24}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v11

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v13

    int-to-long v13, v13

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v15

    move/from16 v25, v2

    int-to-long v2, v15

    shl-long v13, v13, v25

    and-long v2, v2, v21

    or-long v15, v13, v2

    const/16 v18, 0x0

    const/16 v19, 0x0

    const-wide/16 v13, 0x0

    const/16 v17, 0x0

    const/16 v20, 0x78

    invoke-static/range {v10 .. v20}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    invoke-static/range {v23 .. v24}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v2

    invoke-static/range {p1 .. p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v11

    int-to-long v11, v11

    invoke-static/range {p1 .. p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v13

    int-to-long v13, v13

    shl-long v11, v11, v25

    and-long v13, v13, v21

    or-long/2addr v11, v13

    move-object v13, v7

    const/16 v7, 0x78

    move-object v14, v6

    const/4 v6, 0x0

    move-object v15, v10

    move-object v10, v0

    move-object v0, v15

    move-object v15, v9

    move-wide/from16 v26, v2

    move/from16 v3, p1

    move-wide/from16 v28, v11

    move-object v11, v1

    move-wide/from16 v1, v26

    move-object v12, v8

    move-wide v8, v4

    move-wide/from16 v4, v28

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/hg2;->OoooO0(Llyiahf/vczjk/hg2;JFJLlyiahf/vczjk/h79;I)V

    invoke-virtual {v15}, Llyiahf/vczjk/s9;->OooOOo0()V

    iput-object v13, v14, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iput-object v10, v14, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    iput-object v11, v14, Llyiahf/vczjk/fq0;->OooO0OO:Llyiahf/vczjk/eq0;

    iput-wide v8, v14, Llyiahf/vczjk/fq0;->OooO0Oo:J

    return-object v12
.end method

.method public static OooOo(Llyiahf/vczjk/nk1;ILjava/util/ArrayList;Llyiahf/vczjk/lma;)Llyiahf/vczjk/lma;
    .locals 7

    if-nez p1, :cond_0

    iget v0, p0, Llyiahf/vczjk/nk1;->o00ooo:I

    goto :goto_0

    :cond_0
    iget v0, p0, Llyiahf/vczjk/nk1;->oo000o:I

    :goto_0
    const/4 v1, 0x0

    const/4 v2, -0x1

    if-eq v0, v2, :cond_4

    if-eqz p3, :cond_1

    iget v3, p3, Llyiahf/vczjk/lma;->OooO0O0:I

    if-eq v0, v3, :cond_4

    :cond_1
    move v3, v1

    :goto_1
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    move-result v4

    if-ge v3, v4, :cond_5

    invoke-virtual {p2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/lma;

    iget v5, v4, Llyiahf/vczjk/lma;->OooO0O0:I

    if-ne v5, v0, :cond_3

    if-eqz p3, :cond_2

    invoke-virtual {p3, p1, v4}, Llyiahf/vczjk/lma;->OooO0OO(ILlyiahf/vczjk/lma;)V

    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_2
    move-object p3, v4

    goto :goto_2

    :cond_3
    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_4
    if-eq v0, v2, :cond_5

    return-object p3

    :cond_5
    :goto_2
    const/4 v0, 0x1

    if-nez p3, :cond_c

    instance-of v3, p0, Llyiahf/vczjk/in3;

    if-eqz v3, :cond_a

    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/in3;

    move v4, v1

    :goto_3
    iget v5, v3, Llyiahf/vczjk/in3;->o00oO0O:I

    if-ge v4, v5, :cond_8

    iget-object v5, v3, Llyiahf/vczjk/in3;->o00oO0o:[Llyiahf/vczjk/nk1;

    aget-object v5, v5, v4

    if-nez p1, :cond_6

    iget v6, v5, Llyiahf/vczjk/nk1;->o00ooo:I

    if-eq v6, v2, :cond_6

    goto :goto_4

    :cond_6
    if-ne p1, v0, :cond_7

    iget v6, v5, Llyiahf/vczjk/nk1;->oo000o:I

    if-eq v6, v2, :cond_7

    goto :goto_4

    :cond_7
    add-int/lit8 v4, v4, 0x1

    goto :goto_3

    :cond_8
    move v6, v2

    :goto_4
    if-eq v6, v2, :cond_a

    move v3, v1

    :goto_5
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    move-result v4

    if-ge v3, v4, :cond_a

    invoke-virtual {p2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/lma;

    iget v5, v4, Llyiahf/vczjk/lma;->OooO0O0:I

    if-ne v5, v6, :cond_9

    move-object p3, v4

    goto :goto_6

    :cond_9
    add-int/lit8 v3, v3, 0x1

    goto :goto_5

    :cond_a
    :goto_6
    if-nez p3, :cond_b

    new-instance p3, Llyiahf/vczjk/lma;

    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    iput-object v3, p3, Llyiahf/vczjk/lma;->OooO00o:Ljava/util/ArrayList;

    const/4 v3, 0x0

    iput-object v3, p3, Llyiahf/vczjk/lma;->OooO0Oo:Ljava/util/ArrayList;

    iput v2, p3, Llyiahf/vczjk/lma;->OooO0o0:I

    sget v2, Llyiahf/vczjk/lma;->OooO0o:I

    add-int/lit8 v3, v2, 0x1

    sput v3, Llyiahf/vczjk/lma;->OooO0o:I

    iput v2, p3, Llyiahf/vczjk/lma;->OooO0O0:I

    iput p1, p3, Llyiahf/vczjk/lma;->OooO0OO:I

    :cond_b
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_c
    iget-object v2, p3, Llyiahf/vczjk/lma;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v2, p0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_d

    return-object p3

    :cond_d
    invoke-virtual {v2, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    instance-of v2, p0, Llyiahf/vczjk/uk3;

    if-eqz v2, :cond_f

    move-object v2, p0

    check-cast v2, Llyiahf/vczjk/uk3;

    iget-object v3, v2, Llyiahf/vczjk/uk3;->o0ooOOo:Llyiahf/vczjk/nj1;

    iget v2, v2, Llyiahf/vczjk/uk3;->o0ooOoO:I

    if-nez v2, :cond_e

    move v1, v0

    :cond_e
    invoke-virtual {v3, v1, p2, p3}, Llyiahf/vczjk/nj1;->OooO0OO(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    :cond_f
    iget v0, p3, Llyiahf/vczjk/lma;->OooO0O0:I

    if-nez p1, :cond_10

    iput v0, p0, Llyiahf/vczjk/nk1;->o00ooo:I

    iget-object v0, p0, Llyiahf/vczjk/nk1;->Oooo0:Llyiahf/vczjk/nj1;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/nj1;->OooO0OO(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    iget-object v0, p0, Llyiahf/vczjk/nk1;->Oooo0OO:Llyiahf/vczjk/nj1;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/nj1;->OooO0OO(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    goto :goto_7

    :cond_10
    iput v0, p0, Llyiahf/vczjk/nk1;->oo000o:I

    iget-object v0, p0, Llyiahf/vczjk/nk1;->Oooo0O0:Llyiahf/vczjk/nj1;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/nj1;->OooO0OO(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    iget-object v0, p0, Llyiahf/vczjk/nk1;->Oooo0o:Llyiahf/vczjk/nj1;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/nj1;->OooO0OO(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    iget-object v0, p0, Llyiahf/vczjk/nk1;->Oooo0o0:Llyiahf/vczjk/nj1;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/nj1;->OooO0OO(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    :goto_7
    iget-object p0, p0, Llyiahf/vczjk/nk1;->Oooo:Llyiahf/vczjk/nj1;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/nj1;->OooO0OO(ILjava/util/ArrayList;Llyiahf/vczjk/lma;)V

    return-object p3
.end method

.method public static final OooOo00(Llyiahf/vczjk/y05;Llyiahf/vczjk/y05;)Ljava/util/ArrayList;
    .locals 12

    const-string v0, "f1"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "f2"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/e21;->Oooo0oO(Ljava/util/Collection;)Llyiahf/vczjk/x14;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/v14;->OooO00o()Llyiahf/vczjk/w14;

    move-result-object v0

    iget-boolean v1, v0, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-eqz v1, :cond_9

    invoke-virtual {v0}, Llyiahf/vczjk/n14;->OooO00o()I

    move-result v1

    iget-boolean v2, v0, Llyiahf/vczjk/w14;->OooOOOO:Z

    const/4 v3, 0x0

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0, v3}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ia7;

    iget-object v2, v2, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ia7;

    iget-object v4, v4, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    invoke-static {v2, v4}, Llyiahf/vczjk/nqa;->OooOo0O(Llyiahf/vczjk/jw2;Llyiahf/vczjk/jw2;)F

    move-result v2

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/n14;->OooO00o()I

    move-result v4

    invoke-virtual {p0, v3}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ia7;

    iget-object v5, v5, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    invoke-virtual {p1, v4}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ia7;

    iget-object v6, v6, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    invoke-static {v5, v6}, Llyiahf/vczjk/nqa;->OooOo0O(Llyiahf/vczjk/jw2;Llyiahf/vczjk/jw2;)F

    move-result v5

    invoke-static {v2, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    if-lez v6, :cond_2

    move v1, v4

    move v2, v5

    :cond_2
    iget-boolean v4, v0, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-nez v4, :cond_1

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/y05;->OooO00o()I

    move-result v0

    invoke-virtual {p1}, Llyiahf/vczjk/y05;->OooO00o()I

    move-result v2

    const/4 v4, 0x1

    new-array v5, v4, [Llyiahf/vczjk/ia7;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v6

    aput-object v6, v5, v3

    invoke-static {v5}, Llyiahf/vczjk/e21;->OoooO0([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v3

    move v6, v1

    move v5, v4

    :goto_1
    if-ge v5, v0, :cond_8

    sub-int v7, v0, v5

    sub-int v7, v1, v7

    if-le v7, v6, :cond_3

    goto :goto_2

    :cond_3
    add-int/2addr v7, v2

    :goto_2
    new-instance v8, Llyiahf/vczjk/x14;

    add-int/lit8 v6, v6, 0x1

    invoke-direct {v8, v6, v7, v4}, Llyiahf/vczjk/v14;-><init>(III)V

    invoke-virtual {v8}, Llyiahf/vczjk/v14;->OooO00o()Llyiahf/vczjk/w14;

    move-result-object v6

    iget-boolean v7, v6, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-eqz v7, :cond_7

    invoke-virtual {v6}, Llyiahf/vczjk/n14;->OooO00o()I

    move-result v7

    iget-boolean v8, v6, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-nez v8, :cond_4

    :goto_3
    move v6, v7

    goto :goto_4

    :cond_4
    invoke-virtual {p0, v5}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ia7;

    iget-object v8, v8, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    rem-int v9, v7, v2

    invoke-virtual {p1, v9}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ia7;

    iget-object v9, v9, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    invoke-static {v8, v9}, Llyiahf/vczjk/nqa;->OooOo0O(Llyiahf/vczjk/jw2;Llyiahf/vczjk/jw2;)F

    move-result v8

    :cond_5
    invoke-virtual {v6}, Llyiahf/vczjk/n14;->OooO00o()I

    move-result v9

    invoke-virtual {p0, v5}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/ia7;

    iget-object v10, v10, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    rem-int v11, v9, v2

    invoke-virtual {p1, v11}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/ia7;

    iget-object v11, v11, Llyiahf/vczjk/ia7;->OooO0O0:Llyiahf/vczjk/jw2;

    invoke-static {v10, v11}, Llyiahf/vczjk/nqa;->OooOo0O(Llyiahf/vczjk/jw2;Llyiahf/vczjk/jw2;)F

    move-result v10

    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    move-result v11

    if-lez v11, :cond_6

    move v7, v9

    move v8, v10

    :cond_6
    iget-boolean v9, v6, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-nez v9, :cond_5

    goto :goto_3

    :goto_4
    rem-int v7, v6, v2

    invoke-virtual {p1, v7}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v7

    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    :cond_7
    new-instance p0, Ljava/util/NoSuchElementException;

    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    throw p0

    :cond_8
    return-object v3

    :cond_9
    new-instance p0, Ljava/util/NoSuchElementException;

    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    throw p0
.end method

.method public static final OooOo0O(Llyiahf/vczjk/jw2;Llyiahf/vczjk/jw2;)F
    .locals 5

    const-string v0, "f1"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "f2"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/hw2;

    if-eqz v0, :cond_0

    instance-of v0, p1, Llyiahf/vczjk/hw2;

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/hw2;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/hw2;

    iget-boolean v0, v0, Llyiahf/vczjk/hw2;->OooO0Oo:Z

    iget-boolean v1, v1, Llyiahf/vczjk/hw2;->OooO0Oo:Z

    if-eq v0, v1, :cond_0

    const p0, 0x7f7fffff    # Float.MAX_VALUE

    return p0

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/jw2;->OooO00o:Ljava/util/List;

    invoke-static {p0}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/bu1;

    iget-object v0, v0, Llyiahf/vczjk/bu1;->OooO00o:[F

    const/4 v1, 0x0

    aget v0, v0, v1

    invoke-static {p0}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/bu1;

    invoke-virtual {v2}, Llyiahf/vczjk/bu1;->OooO00o()F

    move-result v2

    add-float/2addr v2, v0

    const/high16 v0, 0x40000000    # 2.0f

    div-float/2addr v2, v0

    invoke-static {p0}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/bu1;

    iget-object v3, v3, Llyiahf/vczjk/bu1;->OooO00o:[F

    const/4 v4, 0x1

    aget v3, v3, v4

    invoke-static {p0}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/bu1;

    invoke-virtual {p0}, Llyiahf/vczjk/bu1;->OooO0O0()F

    move-result p0

    add-float/2addr p0, v3

    div-float/2addr p0, v0

    iget-object p1, p1, Llyiahf/vczjk/jw2;->OooO00o:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/bu1;

    iget-object v3, v3, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v1, v3, v1

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/bu1;

    invoke-virtual {v3}, Llyiahf/vczjk/bu1;->OooO00o()F

    move-result v3

    add-float/2addr v3, v1

    div-float/2addr v3, v0

    invoke-static {p1}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/bu1;

    iget-object v1, v1, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v1, v1, v4

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bu1;

    invoke-virtual {p1}, Llyiahf/vczjk/bu1;->OooO0O0()F

    move-result p1

    add-float/2addr p1, v1

    div-float/2addr p1, v0

    sub-float/2addr v2, v3

    sub-float/2addr p0, p1

    mul-float/2addr v2, v2

    mul-float/2addr p0, p0

    add-float/2addr p0, v2

    return p0
.end method

.method public static final OooOo0o(Llyiahf/vczjk/jka;Llyiahf/vczjk/an;)Llyiahf/vczjk/gy9;
    .locals 5

    check-cast p0, Llyiahf/vczjk/ml9;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p0, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p0

    iget-object v0, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    const/16 v1, 0x64

    invoke-static {p0, v1}, Ljava/lang/Math;->min(II)I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_0

    invoke-static {v4, v0, v4}, Llyiahf/vczjk/nqa;->OoooOOo(III)V

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    invoke-static {p0, v0, p0}, Llyiahf/vczjk/nqa;->OoooOOo(III)V

    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    move-result v1

    :goto_1
    if-ge v3, v1, :cond_1

    invoke-static {v3, p0, v3}, Llyiahf/vczjk/nqa;->OoooOo0(III)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_1
    invoke-static {v0, p0, v0}, Llyiahf/vczjk/nqa;->OoooOo0(III)V

    new-instance p0, Llyiahf/vczjk/gy9;

    new-instance v0, Llyiahf/vczjk/yu2;

    iget-object v1, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    iget-object v2, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/yu2;-><init>(II)V

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/gy9;-><init>(Llyiahf/vczjk/an;Llyiahf/vczjk/s86;)V

    return-object p0
.end method

.method public static final OooOoO(Ljava/io/DataInputStream;B)Ljava/io/Serializable;
    .locals 5

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    const/4 v1, 0x1

    if-ne p1, v1, :cond_1

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readBoolean()Z

    move-result p0

    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0

    :cond_1
    const/4 v1, 0x2

    if-ne p1, v1, :cond_2

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readByte()B

    move-result p0

    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p0

    return-object p0

    :cond_2
    const/4 v1, 0x3

    if-ne p1, v1, :cond_3

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_3
    const/4 v1, 0x4

    if-ne p1, v1, :cond_4

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readLong()J

    move-result-wide p0

    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p0

    return-object p0

    :cond_4
    const/4 v1, 0x5

    if-ne p1, v1, :cond_5

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readFloat()F

    move-result p0

    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p0

    return-object p0

    :cond_5
    const/4 v1, 0x6

    if-ne p1, v1, :cond_6

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readDouble()D

    move-result-wide p0

    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p0

    return-object p0

    :cond_6
    const/4 v1, 0x7

    if-ne p1, v1, :cond_7

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readUTF()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_7
    const/16 v1, 0x8

    const/4 v2, 0x0

    if-ne p1, v1, :cond_9

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p1

    new-array v0, p1, [Ljava/lang/Boolean;

    :goto_0
    if-ge v2, p1, :cond_8

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readBoolean()Z

    move-result v1

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    aput-object v1, v0, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_8
    return-object v0

    :cond_9
    const/16 v1, 0x9

    if-ne p1, v1, :cond_b

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p1

    new-array v0, p1, [Ljava/lang/Byte;

    :goto_1
    if-ge v2, p1, :cond_a

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readByte()B

    move-result v1

    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v1

    aput-object v1, v0, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_a
    return-object v0

    :cond_b
    const/16 v1, 0xa

    if-ne p1, v1, :cond_d

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p1

    new-array v0, p1, [Ljava/lang/Integer;

    :goto_2
    if-ge v2, p1, :cond_c

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    aput-object v1, v0, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_c
    return-object v0

    :cond_d
    const/16 v1, 0xb

    if-ne p1, v1, :cond_f

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p1

    new-array v0, p1, [Ljava/lang/Long;

    :goto_3
    if-ge v2, p1, :cond_e

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readLong()J

    move-result-wide v3

    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    aput-object v1, v0, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_3

    :cond_e
    return-object v0

    :cond_f
    const/16 v1, 0xc

    if-ne p1, v1, :cond_11

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p1

    new-array v0, p1, [Ljava/lang/Float;

    :goto_4
    if-ge v2, p1, :cond_10

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readFloat()F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    aput-object v1, v0, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_4

    :cond_10
    return-object v0

    :cond_11
    const/16 v1, 0xd

    if-ne p1, v1, :cond_13

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p1

    new-array v0, p1, [Ljava/lang/Double;

    :goto_5
    if-ge v2, p1, :cond_12

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readDouble()D

    move-result-wide v3

    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    aput-object v1, v0, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_5

    :cond_12
    return-object v0

    :cond_13
    const/16 v1, 0xe

    if-ne p1, v1, :cond_16

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    move-result p1

    new-array v1, p1, [Ljava/lang/String;

    :goto_6
    if-ge v2, p1, :cond_15

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readUTF()Ljava/lang/String;

    move-result-object v3

    const-string v4, "androidx.work.Data-95ed6082-b8e9-46e8-a73f-ff56f00f5d9d"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_14

    move-object v3, v0

    :cond_14
    aput-object v3, v1, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_6

    :cond_15
    return-object v1

    :cond_16
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "Unsupported type "

    invoke-static {p1, v0}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOoO0(Ljava/io/DataInputStream;)V
    .locals 2

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readShort()S

    move-result v0

    const/16 v1, -0x5411

    if-ne v0, v1, :cond_1

    invoke-virtual {p0}, Ljava/io/DataInputStream;->readShort()S

    move-result p0

    const/4 v0, 0x1

    if-ne p0, v0, :cond_0

    return-void

    :cond_0
    const-string v0, "Unsupported version number: "

    invoke-static {p0, v0}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    const-string p0, "Magic number doesn\'t match: "

    invoke-static {v0, p0}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooOoOO(Llyiahf/vczjk/ue8;)Llyiahf/vczjk/or5;
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/ue8;->OooO00o()Llyiahf/vczjk/re8;

    move-result-object p0

    iget-object v0, p0, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->Oooo0()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/or5;

    const/16 v1, 0x30

    invoke-direct {v0, v1}, Llyiahf/vczjk/or5;-><init>(I)V

    invoke-virtual {p0}, Llyiahf/vczjk/re8;->OooO0o0()Llyiahf/vczjk/wj7;

    move-result-object v1

    new-instance v2, Landroid/graphics/Region;

    iget v3, v1, Llyiahf/vczjk/wj7;->OooO00o:F

    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    move-result v3

    iget v4, v1, Llyiahf/vczjk/wj7;->OooO0O0:F

    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    move-result v4

    iget v5, v1, Llyiahf/vczjk/wj7;->OooO0OO:F

    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    move-result v5

    iget v1, v1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    move-result v1

    invoke-direct {v2, v3, v4, v5, v1}, Landroid/graphics/Region;-><init>(IIII)V

    new-instance v1, Landroid/graphics/Region;

    invoke-direct {v1}, Landroid/graphics/Region;-><init>()V

    invoke-static {v2, p0, v0, p0, v1}, Llyiahf/vczjk/nqa;->OooOoo0(Landroid/graphics/Region;Llyiahf/vczjk/re8;Llyiahf/vczjk/or5;Llyiahf/vczjk/re8;Landroid/graphics/Region;)V

    return-object v0

    :cond_1
    :goto_0
    sget-object p0, Llyiahf/vczjk/t14;->OooO00o:Llyiahf/vczjk/or5;

    const-string v0, "null cannot be cast to non-null type androidx.collection.IntObjectMap<V of androidx.collection.IntObjectMapKt.emptyIntObjectMap>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final OooOoo(Llyiahf/vczjk/o34;)Ljava/util/ArrayList;
    .locals 5

    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.node.MeasureScopeWithLayoutNode"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Llyiahf/vczjk/o65;

    invoke-virtual {p0}, Llyiahf/vczjk/o65;->o000OOo()Llyiahf/vczjk/ro4;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/nqa;->Oooo0(Llyiahf/vczjk/ro4;)Z

    move-result v0

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object p0

    new-instance v1, Ljava/util/ArrayList;

    check-cast p0, Llyiahf/vczjk/ts5;

    iget-object v2, p0, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v3, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_1

    invoke-virtual {p0, v3}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ro4;

    if-eqz v0, :cond_0

    invoke-virtual {v4}, Llyiahf/vczjk/ro4;->OooOOO0()Ljava/util/List;

    move-result-object v4

    goto :goto_1

    :cond_0
    invoke-virtual {v4}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object v4

    :goto_1
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    return-object v1
.end method

.method public static final OooOoo0(Landroid/graphics/Region;Llyiahf/vczjk/re8;Llyiahf/vczjk/or5;Llyiahf/vczjk/re8;Landroid/graphics/Region;)V
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    move-object/from16 v4, p4

    iget-object v5, v3, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    invoke-virtual {v5}, Llyiahf/vczjk/ro4;->Oooo0()Z

    move-result v5

    const/4 v6, 0x1

    iget-object v8, v3, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    if-eqz v5, :cond_1

    invoke-virtual {v8}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v5

    if-nez v5, :cond_0

    goto :goto_0

    :cond_0
    const/4 v5, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    move v5, v6

    :goto_1
    invoke-virtual {v0}, Landroid/graphics/Region;->isEmpty()Z

    move-result v9

    iget v10, v1, Llyiahf/vczjk/re8;->OooO0oO:I

    iget v11, v3, Llyiahf/vczjk/re8;->OooO0oO:I

    if-eqz v9, :cond_2

    if-ne v11, v10, :cond_13

    :cond_2
    if-eqz v5, :cond_3

    iget-boolean v5, v3, Llyiahf/vczjk/re8;->OooO0o0:Z

    if-nez v5, :cond_3

    goto/16 :goto_8

    :cond_3
    iget-object v5, v3, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-boolean v9, v5, Llyiahf/vczjk/je8;->OooOOOO:Z

    iget-object v12, v3, Llyiahf/vczjk/re8;->OooO00o:Llyiahf/vczjk/jl5;

    if-eqz v9, :cond_4

    invoke-static {v8}, Llyiahf/vczjk/rl6;->OooOOOo(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/ne8;

    move-result-object v8

    if-eqz v8, :cond_4

    move-object v12, v8

    :cond_4
    check-cast v12, Llyiahf/vczjk/jl5;

    iget-object v8, v12, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    sget-object v9, Llyiahf/vczjk/ie8;->OooO0O0:Llyiahf/vczjk/ze8;

    iget-object v5, v5, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v5, v9}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_5

    const/4 v5, 0x0

    :cond_5
    if-eqz v5, :cond_6

    move v5, v6

    goto :goto_2

    :cond_6
    const/4 v5, 0x0

    :goto_2
    iget-object v9, v8, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v9, v9, Llyiahf/vczjk/jl5;->OooOoO:Z

    sget-object v12, Llyiahf/vczjk/wj7;->OooO0o0:Llyiahf/vczjk/wj7;

    if-nez v9, :cond_7

    goto/16 :goto_4

    :cond_7
    const/16 v9, 0x8

    if-nez v5, :cond_8

    invoke-static {v8, v9}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/ng0;->OooOo0o(Llyiahf/vczjk/xn4;)Llyiahf/vczjk/xn4;

    move-result-object v7

    invoke-interface {v7, v5, v6}, Llyiahf/vczjk/xn4;->OooOOO0(Llyiahf/vczjk/xn4;Z)Llyiahf/vczjk/wj7;

    move-result-object v12

    goto/16 :goto_4

    :cond_8
    invoke-static {v8, v9}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object v8

    iget-boolean v8, v8, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v8, :cond_9

    goto :goto_4

    :cond_9
    invoke-static {v5}, Llyiahf/vczjk/ng0;->OooOo0o(Llyiahf/vczjk/xn4;)Llyiahf/vczjk/xn4;

    move-result-object v8

    iget-object v9, v5, Llyiahf/vczjk/v16;->Oooo0o0:Llyiahf/vczjk/is5;

    if-nez v9, :cond_a

    new-instance v9, Llyiahf/vczjk/is5;

    invoke-direct {v9}, Llyiahf/vczjk/is5;-><init>()V

    iput-object v9, v5, Llyiahf/vczjk/v16;->Oooo0o0:Llyiahf/vczjk/is5;

    :cond_a
    invoke-virtual {v5}, Llyiahf/vczjk/v16;->o0000O0O()J

    move-result-wide v13

    invoke-virtual {v5, v13, v14}, Llyiahf/vczjk/v16;->o00000o0(J)J

    move-result-wide v13

    const/16 v15, 0x20

    shr-long v6, v13, v15

    long-to-int v6, v6

    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v7

    neg-float v7, v7

    iput v7, v9, Llyiahf/vczjk/is5;->OooO00o:F

    const-wide v17, 0xffffffffL

    and-long v13, v13, v17

    long-to-int v7, v13

    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v13

    neg-float v13, v13

    iput v13, v9, Llyiahf/vczjk/is5;->OooO0O0:F

    invoke-virtual {v5}, Llyiahf/vczjk/ow6;->Oooooo()I

    move-result v13

    int-to-float v13, v13

    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v6

    add-float/2addr v6, v13

    iput v6, v9, Llyiahf/vczjk/is5;->OooO0OO:F

    invoke-virtual {v5}, Llyiahf/vczjk/ow6;->OooooOo()I

    move-result v6

    int-to-float v6, v6

    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v7

    add-float/2addr v7, v6

    iput v7, v9, Llyiahf/vczjk/is5;->OooO0Oo:F

    :goto_3
    if-eq v5, v8, :cond_c

    const/4 v6, 0x1

    const/4 v7, 0x0

    invoke-virtual {v5, v9, v7, v6}, Llyiahf/vczjk/v16;->o0000ooO(Llyiahf/vczjk/is5;ZZ)V

    invoke-virtual {v9}, Llyiahf/vczjk/is5;->OooO0O0()Z

    move-result v6

    if-eqz v6, :cond_b

    goto :goto_4

    :cond_b
    iget-object v5, v5, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_3

    :cond_c
    new-instance v12, Llyiahf/vczjk/wj7;

    iget v5, v9, Llyiahf/vczjk/is5;->OooO00o:F

    iget v6, v9, Llyiahf/vczjk/is5;->OooO0O0:F

    iget v7, v9, Llyiahf/vczjk/is5;->OooO0OO:F

    iget v8, v9, Llyiahf/vczjk/is5;->OooO0Oo:F

    invoke-direct {v12, v5, v6, v7, v8}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    :goto_4
    iget v5, v12, Llyiahf/vczjk/wj7;->OooO00o:F

    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    move-result v5

    iget v6, v12, Llyiahf/vczjk/wj7;->OooO0O0:F

    invoke-static {v6}, Ljava/lang/Math;->round(F)I

    move-result v6

    iget v7, v12, Llyiahf/vczjk/wj7;->OooO0OO:F

    invoke-static {v7}, Ljava/lang/Math;->round(F)I

    move-result v7

    iget v8, v12, Llyiahf/vczjk/wj7;->OooO0Oo:F

    invoke-static {v8}, Ljava/lang/Math;->round(F)I

    move-result v8

    invoke-virtual {v4, v5, v6, v7, v8}, Landroid/graphics/Region;->set(IIII)Z

    const/4 v9, -0x1

    if-ne v11, v10, :cond_d

    move v11, v9

    :cond_d
    sget-object v10, Landroid/graphics/Region$Op;->INTERSECT:Landroid/graphics/Region$Op;

    invoke-virtual {v4, v0, v10}, Landroid/graphics/Region;->op(Landroid/graphics/Region;Landroid/graphics/Region$Op;)Z

    move-result v10

    if-eqz v10, :cond_10

    new-instance v10, Llyiahf/vczjk/te8;

    invoke-virtual {v4}, Landroid/graphics/Region;->getBounds()Landroid/graphics/Rect;

    move-result-object v12

    invoke-direct {v10, v3, v12}, Llyiahf/vczjk/te8;-><init>(Llyiahf/vczjk/re8;Landroid/graphics/Rect;)V

    invoke-virtual {v2, v11, v10}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    const/4 v10, 0x4

    invoke-static {v10, v3}, Llyiahf/vczjk/re8;->OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;

    move-result-object v10

    invoke-interface {v10}, Ljava/util/List;->size()I

    move-result v11

    const/16 v16, 0x1

    add-int/lit8 v11, v11, -0x1

    :goto_5
    if-ge v9, v11, :cond_f

    invoke-interface {v10, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/re8;

    invoke-virtual {v12}, Llyiahf/vczjk/re8;->OooO()Llyiahf/vczjk/je8;

    move-result-object v12

    sget-object v13, Llyiahf/vczjk/ve8;->OooOoO0:Llyiahf/vczjk/ze8;

    iget-object v12, v12, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v12, v13}, Llyiahf/vczjk/js5;->OooO0OO(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_e

    goto :goto_6

    :cond_e
    invoke-interface {v10, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/re8;

    invoke-static {v0, v1, v2, v12, v4}, Llyiahf/vczjk/nqa;->OooOoo0(Landroid/graphics/Region;Llyiahf/vczjk/re8;Llyiahf/vczjk/or5;Llyiahf/vczjk/re8;Landroid/graphics/Region;)V

    :goto_6
    add-int/lit8 v11, v11, -0x1

    goto :goto_5

    :cond_f
    invoke-static {v3}, Llyiahf/vczjk/nqa;->Oooo00o(Llyiahf/vczjk/re8;)Z

    move-result v1

    if-eqz v1, :cond_13

    move v1, v5

    sget-object v5, Landroid/graphics/Region$Op;->DIFFERENCE:Landroid/graphics/Region$Op;

    move v2, v6

    move v3, v7

    move v4, v8

    invoke-virtual/range {v0 .. v5}, Landroid/graphics/Region;->op(IIIILandroid/graphics/Region$Op;)Z

    return-void

    :cond_10
    iget-boolean v0, v3, Llyiahf/vczjk/re8;->OooO0o0:Z

    if-eqz v0, :cond_12

    invoke-virtual {v3}, Llyiahf/vczjk/re8;->OooOO0()Llyiahf/vczjk/re8;

    move-result-object v0

    if-eqz v0, :cond_11

    iget-object v1, v0, Llyiahf/vczjk/re8;->OooO0OO:Llyiahf/vczjk/ro4;

    if-eqz v1, :cond_11

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->Oooo0()Z

    move-result v1

    const/4 v6, 0x1

    if-ne v1, v6, :cond_11

    invoke-virtual {v0}, Llyiahf/vczjk/re8;->OooO0o0()Llyiahf/vczjk/wj7;

    move-result-object v0

    goto :goto_7

    :cond_11
    sget-object v0, Llyiahf/vczjk/nqa;->OooO0o0:Llyiahf/vczjk/wj7;

    :goto_7
    new-instance v1, Llyiahf/vczjk/te8;

    new-instance v4, Landroid/graphics/Rect;

    iget v5, v0, Llyiahf/vczjk/wj7;->OooO00o:F

    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    move-result v5

    iget v6, v0, Llyiahf/vczjk/wj7;->OooO0O0:F

    invoke-static {v6}, Ljava/lang/Math;->round(F)I

    move-result v6

    iget v7, v0, Llyiahf/vczjk/wj7;->OooO0OO:F

    invoke-static {v7}, Ljava/lang/Math;->round(F)I

    move-result v7

    iget v0, v0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    move-result v0

    invoke-direct {v4, v5, v6, v7, v0}, Landroid/graphics/Rect;-><init>(IIII)V

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/te8;-><init>(Llyiahf/vczjk/re8;Landroid/graphics/Rect;)V

    invoke-virtual {v2, v11, v1}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    return-void

    :cond_12
    if-ne v11, v9, :cond_13

    new-instance v0, Llyiahf/vczjk/te8;

    invoke-virtual {v4}, Landroid/graphics/Region;->getBounds()Landroid/graphics/Rect;

    move-result-object v1

    invoke-direct {v0, v3, v1}, Llyiahf/vczjk/te8;-><init>(Llyiahf/vczjk/re8;Landroid/graphics/Rect;)V

    invoke-virtual {v2, v11, v0}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    :cond_13
    :goto_8
    return-void
.end method

.method public static final OooOooO()Llyiahf/vczjk/qv3;
    .locals 12

    sget-object v0, Llyiahf/vczjk/nqa;->OooO:Llyiahf/vczjk/qv3;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/pv3;

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-string v2, "Filled.ClearAll"

    const/high16 v3, 0x41c00000    # 24.0f

    const/high16 v4, 0x41c00000    # 24.0f

    const/high16 v5, 0x41c00000    # 24.0f

    const/high16 v6, 0x41c00000    # 24.0f

    const-wide/16 v7, 0x0

    const/16 v11, 0x60

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/gx8;

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v2, Llyiahf/vczjk/jq;

    const/4 v3, 0x1

    invoke-direct {v2, v3}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v3, 0x40a00000    # 5.0f

    const/high16 v4, 0x41500000    # 13.0f

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v4, 0x41600000    # 14.0f

    invoke-virtual {v2, v4}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v5, -0x40000000    # -2.0f

    invoke-virtual {v2, v5}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v6, 0x41300000    # 11.0f

    invoke-virtual {v2, v3, v6}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v3, 0x40000000    # 2.0f

    invoke-virtual {v2, v3}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v2}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v6, 0x40400000    # 3.0f

    const/high16 v7, 0x41880000    # 17.0f

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v5, 0x41700000    # 15.0f

    invoke-virtual {v2, v6, v5}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v2}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v5, 0x40e00000    # 7.0f

    invoke-virtual {v2, v5, v5}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v3, 0x41a80000    # 21.0f

    invoke-virtual {v2, v3, v5}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v2, v5, v5}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v2}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v2, v2, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v1}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/nqa;->OooO:Llyiahf/vczjk/qv3;

    return-object v0
.end method

.method public static OooOooo(Landroid/os/Bundle;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/o0O0o0;->OooO0o0(Landroid/os/Bundle;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    :cond_0
    invoke-virtual {p0, p1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object p0

    const-class p1, Landroidx/activity/result/ActivityResult;

    invoke-virtual {p1, p0}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    return-object p0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final Oooo(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 5

    const-string v0, "collection"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {p0}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-nez v0, :cond_0

    array-length p0, p1

    if-lez p0, :cond_1

    aput-object v1, p1, v2

    return-object p1

    :cond_0
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-nez v3, :cond_2

    array-length p0, p1

    if-lez p0, :cond_1

    aput-object v1, p1, v2

    :cond_1
    return-object p1

    :cond_2
    array-length v3, p1

    if-gt v0, v3, :cond_3

    move-object v0, p1

    goto :goto_0

    :cond_3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v3

    invoke-static {v3, v0}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v0

    const-string v3, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, [Ljava/lang/Object;

    :goto_0
    add-int/lit8 v3, v2, 0x1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    aput-object v4, v0, v2

    array-length v2, v0

    const-string v4, "copyOf(...)"

    if-lt v3, v2, :cond_8

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-nez v2, :cond_4

    return-object v0

    :cond_4
    mul-int/lit8 v2, v3, 0x3

    add-int/lit8 v2, v2, 0x1

    ushr-int/lit8 v2, v2, 0x1

    if-gt v2, v3, :cond_6

    const v2, 0x7ffffffd

    if-ge v3, v2, :cond_5

    goto :goto_1

    :cond_5
    new-instance p0, Ljava/lang/OutOfMemoryError;

    invoke-direct {p0}, Ljava/lang/OutOfMemoryError;-><init>()V

    throw p0

    :cond_6
    :goto_1
    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_7
    move v2, v3

    goto :goto_0

    :cond_8
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-nez v2, :cond_7

    if-ne v0, p1, :cond_9

    aput-object v1, p1, v3

    return-object p1

    :cond_9
    invoke-static {v0, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final Oooo0(Llyiahf/vczjk/ro4;)Z
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_3

    const/4 v1, 0x1

    if-eq v0, v1, :cond_2

    const/4 v2, 0x2

    if-eq v0, v2, :cond_3

    const/4 v2, 0x3

    if-eq v0, v2, :cond_2

    const/4 v1, 0x4

    if-ne v0, v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/nqa;->Oooo0(Llyiahf/vczjk/ro4;)Z

    move-result p0

    return p0

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "no parent for idle node"

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_2
    return v1

    :cond_3
    const/4 p0, 0x0

    return p0
.end method

.method public static final Oooo000(Llyiahf/vczjk/je8;)Llyiahf/vczjk/mm9;
    .locals 2

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    sget-object v1, Llyiahf/vczjk/ie8;->OooO00o:Llyiahf/vczjk/ze8;

    iget-object p0, p0, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    const/4 v1, 0x0

    if-nez p0, :cond_0

    move-object p0, v1

    :cond_0
    check-cast p0, Llyiahf/vczjk/o0O00O;

    if-eqz p0, :cond_1

    iget-object p0, p0, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    check-cast p0, Llyiahf/vczjk/oe3;

    if-eqz p0, :cond_1

    invoke-interface {p0, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    if-eqz p0, :cond_1

    const/4 p0, 0x0

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/mm9;

    return-object p0

    :cond_1
    return-object v1
.end method

.method public static final Oooo00O(Llyiahf/vczjk/re8;)Z
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/re8;->OooO0OO()Llyiahf/vczjk/v16;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000OoO()Z

    move-result v0

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/ve8;->OooO00o:Llyiahf/vczjk/ze8;

    sget-object v0, Llyiahf/vczjk/ve8;->OooOOOO:Llyiahf/vczjk/ze8;

    iget-object p0, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-object v2, p0, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/js5;->OooO0OO(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/ve8;->OooOOO:Llyiahf/vczjk/ze8;

    iget-object p0, p0, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/js5;->OooO0OO(Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_1

    goto :goto_1

    :cond_1
    return v1

    :cond_2
    :goto_1
    const/4 p0, 0x1

    return p0
.end method

.method public static final Oooo00o(Llyiahf/vczjk/re8;)Z
    .locals 14

    invoke-static {p0}, Llyiahf/vczjk/nqa;->Oooo00O(Llyiahf/vczjk/re8;)Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_4

    iget-object p0, p0, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-boolean v0, p0, Llyiahf/vczjk/je8;->OooOOOO:Z

    if-nez v0, :cond_3

    iget-object p0, p0, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    iget-object v0, p0, Llyiahf/vczjk/js5;->OooO0O0:[Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/js5;->OooO0OO:[Ljava/lang/Object;

    iget-object p0, p0, Llyiahf/vczjk/js5;->OooO00o:[J

    array-length v3, p0

    add-int/lit8 v3, v3, -0x2

    if-ltz v3, :cond_4

    move v4, v1

    :goto_0
    aget-wide v5, p0, v4

    not-long v7, v5

    const/4 v9, 0x7

    shl-long/2addr v7, v9

    and-long/2addr v7, v5

    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v7, v9

    cmp-long v7, v7, v9

    if-eqz v7, :cond_2

    sub-int v7, v4, v3

    not-int v7, v7

    ushr-int/lit8 v7, v7, 0x1f

    const/16 v8, 0x8

    rsub-int/lit8 v7, v7, 0x8

    move v9, v1

    :goto_1
    if-ge v9, v7, :cond_1

    const-wide/16 v10, 0xff

    and-long/2addr v10, v5

    const-wide/16 v12, 0x80

    cmp-long v10, v10, v12

    if-gez v10, :cond_0

    shl-int/lit8 v10, v4, 0x3

    add-int/2addr v10, v9

    aget-object v11, v0, v10

    aget-object v10, v2, v10

    check-cast v11, Llyiahf/vczjk/ze8;

    iget-boolean v10, v11, Llyiahf/vczjk/ze8;->OooO0OO:Z

    if-eqz v10, :cond_0

    goto :goto_2

    :cond_0
    shr-long/2addr v5, v8

    add-int/lit8 v9, v9, 0x1

    goto :goto_1

    :cond_1
    if-ne v7, v8, :cond_4

    :cond_2
    if-eq v4, v3, :cond_4

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_3
    :goto_2
    const/4 p0, 0x1

    return p0

    :cond_4
    return v1
.end method

.method public static final Oooo0O0(Landroid/os/Handler;Llyiahf/vczjk/x3;I)V
    .locals 8

    new-instance v1, Llyiahf/vczjk/fl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iput p2, v1, Llyiahf/vczjk/fl7;->element:I

    const/4 p2, -0x1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/x3;->OooO0Oo(I)Landroid/widget/Button;

    move-result-object v3

    const/4 p2, -0x3

    invoke-virtual {p1, p2}, Llyiahf/vczjk/x3;->OooO0Oo(I)Landroid/widget/Button;

    move-result-object v5

    const-string p2, ""

    if-eqz v3, :cond_1

    invoke-virtual {v3}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    move-object v4, v0

    goto :goto_1

    :cond_1
    :goto_0
    move-object v4, p2

    :goto_1
    if-eqz v5, :cond_3

    invoke-virtual {v5}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    move-result-object v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    move-object v6, v0

    goto :goto_3

    :cond_3
    :goto_2
    move-object v6, p2

    :goto_3
    const/4 p2, 0x0

    if-eqz v3, :cond_4

    invoke-virtual {v3, p2}, Landroid/view/View;->setEnabled(Z)V

    :cond_4
    if-eqz v5, :cond_5

    invoke-virtual {v5, p2}, Landroid/view/View;->setEnabled(Z)V

    :cond_5
    invoke-virtual {p1}, Landroid/app/Dialog;->isShowing()Z

    move-result p2

    const-string v0, "s"

    const-string v2, " "

    if-eqz p2, :cond_6

    if-eqz v3, :cond_6

    iget p2, v1, Llyiahf/vczjk/fl7;->element:I

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v3, p2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_6
    invoke-virtual {p1}, Landroid/app/Dialog;->isShowing()Z

    move-result p2

    if-eqz p2, :cond_7

    if-eqz v5, :cond_7

    iget p2, v1, Llyiahf/vczjk/fl7;->element:I

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v5, p2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_7
    new-instance v0, Llyiahf/vczjk/ba2;

    move-object v7, p0

    move-object v2, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/ba2;-><init>(Llyiahf/vczjk/fl7;Llyiahf/vczjk/x3;Landroid/widget/Button;Ljava/lang/CharSequence;Landroid/widget/Button;Ljava/lang/CharSequence;Landroid/os/Handler;)V

    const-wide/16 p0, 0x3e8

    invoke-virtual {v7, v0, p0, p1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    return-void
.end method

.method public static final Oooo0OO(Landroid/view/View;Ljava/lang/Integer;Landroid/graphics/Rect;)Z
    .locals 3

    if-nez p1, :cond_0

    invoke-virtual {p0}, Landroid/view/View;->requestFocus()Z

    move-result p0

    return p0

    :cond_0
    instance-of v0, p0, Landroid/view/ViewGroup;

    if-nez v0, :cond_1

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-virtual {p0, p1, p2}, Landroid/view/View;->requestFocus(ILandroid/graphics/Rect;)Z

    move-result p0

    return p0

    :cond_1
    move-object v0, p0

    check-cast v0, Landroid/view/ViewGroup;

    invoke-virtual {v0}, Landroid/view/View;->isFocused()Z

    move-result v1

    if-eqz v1, :cond_2

    const/4 p0, 0x1

    return p0

    :cond_2
    invoke-virtual {v0}, Landroid/view/View;->isFocusable()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {p0}, Landroid/view/View;->hasFocus()Z

    move-result v1

    if-nez v1, :cond_3

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-virtual {p0, p1, p2}, Landroid/view/View;->requestFocus(ILandroid/graphics/Rect;)Z

    move-result p0

    return p0

    :cond_3
    instance-of v1, p0, Llyiahf/vczjk/xa;

    if-eqz v1, :cond_4

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-virtual {p0, p1, p2}, Landroid/view/View;->requestFocus(ILandroid/graphics/Rect;)Z

    move-result p0

    return p0

    :cond_4
    if-eqz p2, :cond_6

    invoke-static {}, Landroid/view/FocusFinder;->getInstance()Landroid/view/FocusFinder;

    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result v2

    invoke-virtual {v1, v0, p2, v2}, Landroid/view/FocusFinder;->findNextFocusFromRect(Landroid/view/ViewGroup;Landroid/graphics/Rect;I)Landroid/view/View;

    move-result-object v0

    if-eqz v0, :cond_5

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p0

    invoke-virtual {v0, p0, p2}, Landroid/view/View;->requestFocus(ILandroid/graphics/Rect;)Z

    move-result p0

    return p0

    :cond_5
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-virtual {p0, p1, p2}, Landroid/view/View;->requestFocus(ILandroid/graphics/Rect;)Z

    move-result p0

    return p0

    :cond_6
    invoke-virtual {p0}, Landroid/view/View;->hasFocus()Z

    move-result p2

    if-eqz p2, :cond_7

    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    move-result-object p2

    goto :goto_0

    :cond_7
    const/4 p2, 0x0

    :goto_0
    invoke-static {}, Landroid/view/FocusFinder;->getInstance()Landroid/view/FocusFinder;

    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result v2

    invoke-virtual {v1, v0, p2, v2}, Landroid/view/FocusFinder;->findNextFocus(Landroid/view/ViewGroup;Landroid/view/View;I)Landroid/view/View;

    move-result-object p2

    if-eqz p2, :cond_8

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p0

    invoke-virtual {p2, p0}, Landroid/view/View;->requestFocus(I)Z

    move-result p0

    return p0

    :cond_8
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-virtual {p0, p1}, Landroid/view/View;->requestFocus(I)Z

    move-result p0

    return p0
.end method

.method public static final Oooo0o(Llyiahf/vczjk/th;I)Llyiahf/vczjk/nh;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/th;->getLayoutNodeToHolder()Ljava/util/HashMap;

    move-result-object p0

    invoke-virtual {p0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    move-result-object p0

    check-cast p0, Ljava/lang/Iterable;

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Ljava/util/Map$Entry;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ro4;

    iget v2, v2, Llyiahf/vczjk/ro4;->OooOOO:I

    if-ne v2, p1, :cond_0

    goto :goto_0

    :cond_1
    move-object v0, v1

    :goto_0
    check-cast v0, Ljava/util/Map$Entry;

    if-eqz v0, :cond_2

    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/nh;

    return-object p0

    :cond_2
    return-object v1
.end method

.method public static Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V
    .locals 0

    if-eqz p0, :cond_0

    return-void

    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final Oooo0oO(I)Ljava/lang/Integer;
    .locals 2

    const/4 v0, 0x5

    if-ne p0, v0, :cond_0

    const/16 p0, 0x21

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 v0, 0x6

    if-ne p0, v0, :cond_1

    const/16 p0, 0x82

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_1
    const/4 v0, 0x3

    if-ne p0, v0, :cond_2

    const/16 p0, 0x11

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_2
    const/4 v0, 0x4

    if-ne p0, v0, :cond_3

    const/16 p0, 0x42

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_3
    const/4 v0, 0x2

    const/4 v1, 0x1

    if-ne p0, v1, :cond_4

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_4
    if-ne p0, v0, :cond_5

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_5
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final Oooo0oo(Ljava/util/Collection;)[Ljava/lang/Object;
    .locals 4

    const-string v0, "collection"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Ljava/util/Collection;->size()I

    move-result v0

    sget-object v1, Llyiahf/vczjk/nqa;->OooO00o:[Ljava/lang/Object;

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-nez v2, :cond_1

    return-object v1

    :cond_1
    new-array v0, v0, [Ljava/lang/Object;

    const/4 v1, 0x0

    :goto_0
    add-int/lit8 v2, v1, 0x1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    aput-object v3, v0, v1

    array-length v1, v0

    const-string v3, "copyOf(...)"

    if-lt v2, v1, :cond_6

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_2

    return-object v0

    :cond_2
    mul-int/lit8 v1, v2, 0x3

    add-int/lit8 v1, v1, 0x1

    ushr-int/lit8 v1, v1, 0x1

    if-gt v1, v2, :cond_4

    const v1, 0x7ffffffd

    if-ge v2, v1, :cond_3

    goto :goto_1

    :cond_3
    new-instance p0, Ljava/lang/OutOfMemoryError;

    invoke-direct {p0}, Ljava/lang/OutOfMemoryError;-><init>()V

    throw p0

    :cond_4
    :goto_1
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_5
    move v1, v2

    goto :goto_0

    :cond_6
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_5

    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final OoooO(Ljava/io/DataOutputStream;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    const/4 v2, 0x0

    if-nez v1, :cond_0

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    goto/16 :goto_9

    :cond_0
    instance-of v3, v1, Ljava/lang/Boolean;

    if-eqz v3, :cond_1

    const/4 v2, 0x1

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    goto/16 :goto_9

    :cond_1
    instance-of v3, v1, Ljava/lang/Byte;

    if-eqz v3, :cond_2

    const/4 v2, 0x2

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->byteValue()B

    move-result v1

    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeByte(I)V

    goto/16 :goto_9

    :cond_2
    instance-of v3, v1, Ljava/lang/Integer;

    if-eqz v3, :cond_3

    const/4 v2, 0x3

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeInt(I)V

    goto/16 :goto_9

    :cond_3
    instance-of v3, v1, Ljava/lang/Long;

    if-eqz v3, :cond_4

    const/4 v2, 0x4

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->longValue()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/io/DataOutputStream;->writeLong(J)V

    goto/16 :goto_9

    :cond_4
    instance-of v3, v1, Ljava/lang/Float;

    if-eqz v3, :cond_5

    const/4 v2, 0x5

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeFloat(F)V

    goto/16 :goto_9

    :cond_5
    instance-of v3, v1, Ljava/lang/Double;

    if-eqz v3, :cond_6

    const/4 v2, 0x6

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/io/DataOutputStream;->writeDouble(D)V

    goto/16 :goto_9

    :cond_6
    instance-of v3, v1, Ljava/lang/String;

    if-eqz v3, :cond_7

    const/4 v2, 0x7

    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeUTF(Ljava/lang/String;)V

    goto/16 :goto_9

    :cond_7
    instance-of v3, v1, [Ljava/lang/Object;

    const-string v4, "Unsupported value type "

    if-eqz v3, :cond_25

    check-cast v1, [Ljava/lang/Object;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v3

    const-class v6, [Ljava/lang/Boolean;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v6

    const/16 v7, 0xe

    const/16 v8, 0xd

    const/16 v9, 0xc

    const/16 v10, 0xb

    const/16 v11, 0xa

    const/16 v12, 0x9

    const/16 v13, 0x8

    if-eqz v6, :cond_8

    move v3, v13

    goto :goto_0

    :cond_8
    const-class v6, [Ljava/lang/Byte;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_9

    move v3, v12

    goto :goto_0

    :cond_9
    const-class v6, [Ljava/lang/Integer;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_a

    move v3, v11

    goto :goto_0

    :cond_a
    const-class v6, [Ljava/lang/Long;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_b

    move v3, v10

    goto :goto_0

    :cond_b
    const-class v6, [Ljava/lang/Float;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_c

    move v3, v9

    goto :goto_0

    :cond_c
    const-class v6, [Ljava/lang/Double;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_d

    move v3, v8

    goto :goto_0

    :cond_d
    const-class v6, [Ljava/lang/String;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_24

    move v3, v7

    :goto_0
    invoke-virtual {v0, v3}, Ljava/io/DataOutputStream;->writeByte(I)V

    array-length v4, v1

    invoke-virtual {v0, v4}, Ljava/io/DataOutputStream;->writeInt(I)V

    array-length v4, v1

    move v5, v2

    :goto_1
    if-ge v5, v4, :cond_23

    aget-object v6, v1, v5

    const/4 v14, 0x0

    if-ne v3, v13, :cond_10

    instance-of v15, v6, Ljava/lang/Boolean;

    if-eqz v15, :cond_e

    move-object v14, v6

    check-cast v14, Ljava/lang/Boolean;

    :cond_e
    if-eqz v14, :cond_f

    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    goto :goto_2

    :cond_f
    move v6, v2

    :goto_2
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    goto/16 :goto_8

    :cond_10
    if-ne v3, v12, :cond_13

    instance-of v15, v6, Ljava/lang/Byte;

    if-eqz v15, :cond_11

    move-object v14, v6

    check-cast v14, Ljava/lang/Byte;

    :cond_11
    if-eqz v14, :cond_12

    invoke-virtual {v14}, Ljava/lang/Byte;->byteValue()B

    move-result v6

    goto :goto_3

    :cond_12
    move v6, v2

    :goto_3
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeByte(I)V

    goto/16 :goto_8

    :cond_13
    if-ne v3, v11, :cond_16

    instance-of v15, v6, Ljava/lang/Integer;

    if-eqz v15, :cond_14

    move-object v14, v6

    check-cast v14, Ljava/lang/Integer;

    :cond_14
    if-eqz v14, :cond_15

    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    move-result v6

    goto :goto_4

    :cond_15
    move v6, v2

    :goto_4
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeInt(I)V

    goto :goto_8

    :cond_16
    if-ne v3, v10, :cond_19

    instance-of v15, v6, Ljava/lang/Long;

    if-eqz v15, :cond_17

    move-object v14, v6

    check-cast v14, Ljava/lang/Long;

    :cond_17
    if-eqz v14, :cond_18

    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    move-result-wide v14

    goto :goto_5

    :cond_18
    const-wide/16 v14, 0x0

    :goto_5
    invoke-virtual {v0, v14, v15}, Ljava/io/DataOutputStream;->writeLong(J)V

    goto :goto_8

    :cond_19
    if-ne v3, v9, :cond_1c

    instance-of v15, v6, Ljava/lang/Float;

    if-eqz v15, :cond_1a

    move-object v14, v6

    check-cast v14, Ljava/lang/Float;

    :cond_1a
    if-eqz v14, :cond_1b

    invoke-virtual {v14}, Ljava/lang/Float;->floatValue()F

    move-result v6

    goto :goto_6

    :cond_1b
    const/4 v6, 0x0

    :goto_6
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeFloat(F)V

    goto :goto_8

    :cond_1c
    if-ne v3, v8, :cond_1f

    instance-of v15, v6, Ljava/lang/Double;

    if-eqz v15, :cond_1d

    move-object v14, v6

    check-cast v14, Ljava/lang/Double;

    :cond_1d
    if-eqz v14, :cond_1e

    invoke-virtual {v14}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v14

    goto :goto_7

    :cond_1e
    const-wide/16 v14, 0x0

    :goto_7
    invoke-virtual {v0, v14, v15}, Ljava/io/DataOutputStream;->writeDouble(D)V

    goto :goto_8

    :cond_1f
    if-ne v3, v7, :cond_22

    instance-of v15, v6, Ljava/lang/String;

    if-eqz v15, :cond_20

    move-object v14, v6

    check-cast v14, Ljava/lang/String;

    :cond_20
    if-nez v14, :cond_21

    const-string v14, "androidx.work.Data-95ed6082-b8e9-46e8-a73f-ff56f00f5d9d"

    :cond_21
    invoke-virtual {v0, v14}, Ljava/io/DataOutputStream;->writeUTF(Ljava/lang/String;)V

    :cond_22
    :goto_8
    add-int/lit8 v5, v5, 0x1

    goto/16 :goto_1

    :cond_23
    :goto_9
    invoke-virtual/range {p0 .. p1}, Ljava/io/DataOutputStream;->writeUTF(Ljava/lang/String;)V

    return-void

    :cond_24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_25
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/gf4;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OoooO0(J)J
    .locals 3

    sget-object v0, Llyiahf/vczjk/gp4;->OooOOO0:Llyiahf/vczjk/gp4;

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v0

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v1

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v2

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p0

    invoke-static {v0, v1, v2, p0}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p0

    return-wide p0
.end method

.method public static OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;
    .locals 8

    and-int/lit8 v0, p3, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move v5, v1

    goto :goto_0

    :cond_0
    move v5, p1

    :goto_0
    and-int/lit8 p1, p3, 0x2

    if-eqz p1, :cond_1

    :goto_1
    move v4, v1

    goto :goto_2

    :cond_1
    const/4 v1, 0x1

    goto :goto_1

    :goto_2
    and-int/lit8 p1, p3, 0x4

    const/4 p3, 0x0

    if-eqz p1, :cond_2

    move-object p2, p3

    :cond_2
    if-eqz p2, :cond_3

    invoke-static {p2}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p3

    :cond_3
    move-object v6, p3

    new-instance v2, Llyiahf/vczjk/a74;

    const/16 v7, 0x22

    move-object v3, p0

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/a74;-><init>(Llyiahf/vczjk/j5a;ZZLjava/util/Set;I)V

    return-object v2
.end method

.method public static OoooO0O(Llyiahf/vczjk/mw1;)[B
    .locals 4

    const-string v0, "data"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    new-instance v1, Ljava/io/DataOutputStream;

    invoke-direct {v1, v0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    const/16 v2, -0x5411

    :try_start_1
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    iget-object p0, p0, Llyiahf/vczjk/mw1;->OooO00o:Ljava/util/HashMap;

    :try_start_2
    invoke-virtual {p0}, Ljava/util/HashMap;->size()I

    move-result v2

    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeInt(I)V

    invoke-virtual {p0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map$Entry;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/nqa;->OoooO(Ljava/io/DataOutputStream;Ljava/lang/String;Ljava/lang/Object;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    invoke-virtual {v1}, Ljava/io/DataOutputStream;->size()I

    move-result p0

    const/16 v2, 0x2800

    if-gt p0, v2, :cond_1

    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :try_start_3
    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    const-string v0, "{\n                ByteAr\u2026          }\n            }"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0

    return-object p0

    :cond_1
    :try_start_4
    const-string p0, "Data cannot occupy more than 10240 bytes when serialized"

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    :goto_1
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    :catchall_1
    move-exception v0

    :try_start_6
    invoke-static {v1, p0}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0

    :catch_0
    move-exception p0

    sget-object v0, Llyiahf/vczjk/nz1;->OooO00o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    const-string v2, "Error in Data#toByteArray: "

    invoke-virtual {v1, v0, v2, p0}, Llyiahf/vczjk/o55;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    const/4 p0, 0x0

    new-array p0, p0, [B

    return-object p0
.end method

.method public static final OoooOO0(I)Llyiahf/vczjk/b83;
    .locals 2

    const/4 v0, 0x2

    const/4 v1, 0x1

    if-eq p0, v1, :cond_5

    if-eq p0, v0, :cond_4

    const/16 v0, 0x11

    if-eq p0, v0, :cond_3

    const/16 v0, 0x21

    if-eq p0, v0, :cond_2

    const/16 v0, 0x42

    if-eq p0, v0, :cond_1

    const/16 v0, 0x82

    if-eq p0, v0, :cond_0

    const/4 p0, 0x0

    return-object p0

    :cond_0
    new-instance p0, Llyiahf/vczjk/b83;

    const/4 v0, 0x6

    invoke-direct {p0, v0}, Llyiahf/vczjk/b83;-><init>(I)V

    return-object p0

    :cond_1
    new-instance p0, Llyiahf/vczjk/b83;

    const/4 v0, 0x4

    invoke-direct {p0, v0}, Llyiahf/vczjk/b83;-><init>(I)V

    return-object p0

    :cond_2
    new-instance p0, Llyiahf/vczjk/b83;

    const/4 v0, 0x5

    invoke-direct {p0, v0}, Llyiahf/vczjk/b83;-><init>(I)V

    return-object p0

    :cond_3
    new-instance p0, Llyiahf/vczjk/b83;

    const/4 v0, 0x3

    invoke-direct {p0, v0}, Llyiahf/vczjk/b83;-><init>(I)V

    return-object p0

    :cond_4
    new-instance p0, Llyiahf/vczjk/b83;

    invoke-direct {p0, v1}, Llyiahf/vczjk/b83;-><init>(I)V

    return-object p0

    :cond_5
    new-instance p0, Llyiahf/vczjk/b83;

    invoke-direct {p0, v0}, Llyiahf/vczjk/b83;-><init>(I)V

    return-object p0
.end method

.method public static OoooOOO(Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;Llyiahf/vczjk/mk1;)Z
    .locals 5

    sget-object v0, Llyiahf/vczjk/mk1;->OooOOO0:Llyiahf/vczjk/mk1;

    sget-object v1, Llyiahf/vczjk/mk1;->OooOOOo:Llyiahf/vczjk/mk1;

    sget-object v2, Llyiahf/vczjk/mk1;->OooOOO:Llyiahf/vczjk/mk1;

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eq p2, v0, :cond_1

    if-eq p2, v2, :cond_1

    if-ne p2, v1, :cond_0

    if-eq p0, v2, :cond_0

    goto :goto_0

    :cond_0
    move p0, v4

    goto :goto_1

    :cond_1
    :goto_0
    move p0, v3

    :goto_1
    if-eq p3, v0, :cond_3

    if-eq p3, v2, :cond_3

    if-ne p3, v1, :cond_2

    if-eq p1, v2, :cond_2

    goto :goto_2

    :cond_2
    move p1, v4

    goto :goto_3

    :cond_3
    :goto_2
    move p1, v3

    :goto_3
    if-nez p0, :cond_5

    if-eqz p1, :cond_4

    goto :goto_4

    :cond_4
    return v4

    :cond_5
    :goto_4
    return v3
.end method

.method public static final OoooOOo(III)V
    .locals 3

    const/4 v0, 0x0

    if-ltz p0, :cond_0

    if-gt p0, p1, :cond_0

    const/4 v0, 0x1

    :cond_0
    if-nez v0, :cond_1

    const-string v0, "OffsetMapping.originalToTransformed returned invalid mapping: "

    const-string v1, " -> "

    const-string v2, " is not in range of transformed text [0, "

    invoke-static {p2, p0, v0, v1, v2}, Llyiahf/vczjk/ii5;->OooOOO0(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 p1, 0x5d

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :cond_1
    return-void
.end method

.method public static final OoooOo0(III)V
    .locals 3

    const/4 v0, 0x0

    if-ltz p0, :cond_0

    if-gt p0, p1, :cond_0

    const/4 v0, 0x1

    :cond_0
    if-nez v0, :cond_1

    const-string v0, "OffsetMapping.transformedToOriginal returned invalid mapping: "

    const-string v1, " -> "

    const-string v2, " is not in range of original text [0, "

    invoke-static {p2, p0, v0, v1, v2}, Llyiahf/vczjk/ii5;->OooOOO0(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 p1, 0x5d

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :cond_1
    return-void
.end method

.method public static final o000oOoO(I)Ljava/lang/String;
    .locals 1

    if-nez p0, :cond_0

    const-string p0, "android.widget.Button"

    return-object p0

    :cond_0
    const/4 v0, 0x1

    if-ne p0, v0, :cond_1

    const-string p0, "android.widget.CheckBox"

    return-object p0

    :cond_1
    const/4 v0, 0x3

    if-ne p0, v0, :cond_2

    const-string p0, "android.widget.RadioButton"

    return-object p0

    :cond_2
    const/4 v0, 0x5

    if-ne p0, v0, :cond_3

    const-string p0, "android.widget.ImageView"

    return-object p0

    :cond_3
    const/4 v0, 0x6

    if-ne p0, v0, :cond_4

    const-string p0, "android.widget.Spinner"

    return-object p0

    :cond_4
    const/4 v0, 0x7

    if-ne p0, v0, :cond_5

    const-string p0, "android.widget.NumberPicker"

    return-object p0

    :cond_5
    const/4 p0, 0x0

    return-object p0
.end method


# virtual methods
.method public OooOo0(Llyiahf/vczjk/yqa;)V
    .locals 4

    const-string v0, "request"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/oqa;

    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/dqa;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/dqa;-><init>(Llyiahf/vczjk/oqa;Ljava/util/List;)V

    iget-boolean p1, v1, Llyiahf/vczjk/dqa;->OooO0oO:Z

    if-nez p1, :cond_0

    iget-object p1, v0, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    iget-object p1, p1, Llyiahf/vczjk/wh1;->OooOOO0:Llyiahf/vczjk/e86;

    iget-object v0, v0, Llyiahf/vczjk/oqa;->OooOOOO:Llyiahf/vczjk/rqa;

    iget-object v0, v0, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    new-instance v2, Llyiahf/vczjk/ku7;

    const/16 v3, 0x13

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    const-string v1, "EnqueueRunnable_KEEP"

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/cp7;->Oooo000(Llyiahf/vczjk/e86;Ljava/lang/String;Ljava/util/concurrent/Executor;Llyiahf/vczjk/le3;)Llyiahf/vczjk/ee6;

    goto :goto_0

    :cond_0
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Already enqueued work ids ("

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/dqa;->OooO0o0:Ljava/util/ArrayList;

    const-string v2, ", "

    invoke-static {v2, v1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/dqa;->OooO0oo:Ljava/lang/String;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/o55;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    :goto_0
    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "enqueue needs at least one WorkRequest."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
