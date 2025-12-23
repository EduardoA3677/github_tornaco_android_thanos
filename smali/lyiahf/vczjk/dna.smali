.class public final Llyiahf/vczjk/dna;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:Llyiahf/vczjk/dna;

.field public static final OooO0O0:Llyiahf/vczjk/sc9;

.field public static final OooO0OO:Llyiahf/vczjk/tp3;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/dna;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/dna;->OooO00o:Llyiahf/vczjk/dna;

    sget-object v0, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v1, Llyiahf/vczjk/ena;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/gf4;->OooO0O0()Ljava/lang/String;

    sget-object v0, Llyiahf/vczjk/o24;->Oooo0O0:Llyiahf/vczjk/o24;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/dna;->OooO0O0:Llyiahf/vczjk/sc9;

    sget-object v0, Llyiahf/vczjk/tp3;->OooOOOo:Llyiahf/vczjk/tp3;

    sput-object v0, Llyiahf/vczjk/dna;->OooO0OO:Llyiahf/vczjk/tp3;

    return-void
.end method

.method public static OooO00o(Landroid/content/Context;)Llyiahf/vczjk/jna;
    .locals 11

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/dna;->OooO0O0:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uma;

    if-nez v0, :cond_5

    sget-object v0, Llyiahf/vczjk/vn8;->OooO0OO:Llyiahf/vczjk/vn8;

    sget-object v0, Llyiahf/vczjk/vn8;->OooO0OO:Llyiahf/vczjk/vn8;

    if-nez v0, :cond_4

    sget-object v1, Llyiahf/vczjk/vn8;->OooO0Oo:Ljava/util/concurrent/locks/ReentrantLock;

    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    :try_start_0
    sget-object v0, Llyiahf/vczjk/vn8;->OooO0OO:Llyiahf/vczjk/vn8;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    if-nez v0, :cond_3

    const/4 v0, 0x0

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/rn8;->OooO0O0()Llyiahf/vczjk/wea;

    move-result-object v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    sget-object v3, Llyiahf/vczjk/wea;->OooOOo:Llyiahf/vczjk/wea;

    const-string v4, "other"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v2, Llyiahf/vczjk/wea;->OooOOo0:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    const-string v4, "getValue(...)"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/math/BigInteger;

    iget-object v3, v3, Llyiahf/vczjk/wea;->OooOOo0:Llyiahf/vczjk/sc9;

    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v3, Ljava/math/BigInteger;

    invoke-virtual {v2, v3}, Ljava/math/BigInteger;->compareTo(Ljava/math/BigInteger;)I

    move-result v2

    if-ltz v2, :cond_2

    new-instance v2, Llyiahf/vczjk/tn8;

    invoke-direct {v2, p0}, Llyiahf/vczjk/tn8;-><init>(Landroid/content/Context;)V

    invoke-virtual {v2}, Llyiahf/vczjk/tn8;->OooO0o0()Z

    move-result p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-nez p0, :cond_1

    goto :goto_0

    :cond_1
    move-object v0, v2

    :catchall_0
    :cond_2
    :goto_0
    :try_start_2
    new-instance p0, Llyiahf/vczjk/vn8;

    invoke-direct {p0, v0}, Llyiahf/vczjk/vn8;-><init>(Llyiahf/vczjk/tn8;)V

    sput-object p0, Llyiahf/vczjk/vn8;->OooO0OO:Llyiahf/vczjk/vn8;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    goto :goto_1

    :catchall_1
    move-exception v0

    move-object p0, v0

    goto :goto_2

    :cond_3
    :goto_1
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    goto :goto_3

    :goto_2
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    throw p0

    :cond_4
    :goto_3
    sget-object v0, Llyiahf/vczjk/vn8;->OooO0OO:Llyiahf/vczjk/vn8;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :cond_5
    new-instance p0, Llyiahf/vczjk/jna;

    new-instance v1, Llyiahf/vczjk/rp3;

    const/16 v2, 0x1b

    invoke-direct {v1, v2}, Llyiahf/vczjk/rp3;-><init>(I)V

    const/4 v2, 0x1

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    const/4 v2, 0x2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    const/4 v2, 0x4

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    const/16 v2, 0x8

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    const/16 v2, 0x10

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    const/16 v2, 0x20

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    const/16 v2, 0x40

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    const/16 v2, 0x80

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    filled-new-array/range {v3 .. v10}, [Ljava/lang/Integer;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo0o0([Ljava/lang/Object;)Ljava/util/ArrayList;

    new-instance v2, Llyiahf/vczjk/sp3;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Llyiahf/vczjk/ru2;->OooO00o()I

    invoke-direct {p0, v1, v0, v2}, Llyiahf/vczjk/jna;-><init>(Llyiahf/vczjk/rp3;Llyiahf/vczjk/uma;Llyiahf/vczjk/sp3;)V

    sget-object v0, Llyiahf/vczjk/dna;->OooO0OO:Llyiahf/vczjk/tp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object p0
.end method
