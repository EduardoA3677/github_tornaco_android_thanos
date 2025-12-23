.class public abstract Llyiahf/vczjk/r02;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO:[Ljava/lang/StackTraceElement;

.field public static final OooO00o:[I

.field public static final OooO0O0:[I

.field public static final OooO0OO:[I

.field public static final OooO0Oo:[I

.field public static final OooO0o:[I

.field public static final OooO0o0:[I

.field public static final OooO0oO:Llyiahf/vczjk/hs1;

.field public static final OooO0oo:[I

.field public static final OooOO0:Llyiahf/vczjk/h87;

.field public static final OooOO0O:Llyiahf/vczjk/h87;

.field public static final synthetic OooOO0o:I

.field public static OooOOO0:Llyiahf/vczjk/qv3;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 5

    const v0, 0x101051e

    const v1, 0x1010405

    const/16 v2, 0x8

    const v3, 0x1010003

    const/16 v4, 0x9

    new-array v4, v4, [I

    fill-array-data v4, :array_0

    sput-object v4, Llyiahf/vczjk/r02;->OooO00o:[I

    new-array v4, v2, [I

    fill-array-data v4, :array_1

    sput-object v4, Llyiahf/vczjk/r02;->OooO0O0:[I

    const/16 v4, 0xe

    new-array v4, v4, [I

    fill-array-data v4, :array_2

    sput-object v4, Llyiahf/vczjk/r02;->OooO0OO:[I

    filled-new-array {v3, v1, v0}, [I

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/r02;->OooO0Oo:[I

    const v0, 0x1010199

    filled-new-array {v0}, [I

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/r02;->OooO0o0:[I

    const v0, 0x10101cd

    filled-new-array {v3, v0}, [I

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/r02;->OooO0o:[I

    new-instance v0, Llyiahf/vczjk/hs1;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/r02;->OooO0oO:Llyiahf/vczjk/hs1;

    const/4 v0, 0x2

    new-array v0, v0, [I

    sput-object v0, Llyiahf/vczjk/r02;->OooO0oo:[I

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/StackTraceElement;

    sput-object v0, Llyiahf/vczjk/r02;->OooO:[Ljava/lang/StackTraceElement;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "NONE"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/r02;->OooOO0:Llyiahf/vczjk/h87;

    new-instance v0, Llyiahf/vczjk/h87;

    const-string v1, "PENDING"

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    sput-object v0, Llyiahf/vczjk/r02;->OooOO0O:Llyiahf/vczjk/h87;

    return-void

    :array_0
    .array-data 4
        0x1010003
        0x1010121
        0x1010155
        0x1010159
        0x101031f
        0x10103ea
        0x10103fb
        0x1010402
        0x1010403
    .end array-data

    :array_1
    .array-data 4
        0x1010003
        0x10101b5
        0x10101b6
        0x1010324
        0x1010325
        0x1010326
        0x101045a
        0x101045b
    .end array-data

    :array_2
    .array-data 4
        0x1010003
        0x1010404
        0x1010405
        0x1010406
        0x1010407
        0x1010408
        0x1010409
        0x101040a
        0x101040b
        0x101040c
        0x101040d
        0x10104cb
        0x10104cc
        0x101051e
    .end array-data
.end method

.method public static OooO(Landroid/database/Cursor;)V
    .locals 0

    if-eqz p0, :cond_0

    :try_start_0
    invoke-static {p0}, Llyiahf/vczjk/u81;->OooOOoo(Ljava/lang/AutoCloseable;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    return-void

    :catch_0
    move-exception p0

    throw p0

    :catch_1
    :cond_0
    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 10

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x50862cb8

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ag1;->OooO0O0:Llyiahf/vczjk/sc6;

    const/16 v2, 0xc9

    invoke-virtual {p2, v2, v1}, Llyiahf/vczjk/zf1;->OoooO00(ILlyiahf/vczjk/sc6;)V

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    move-object v1, v3

    goto :goto_0

    :cond_0
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.ValueHolder<kotlin.Any?>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/ica;

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/ke7;->OooO00o:Landroidx/compose/runtime/OooO;

    invoke-virtual {v2, p0, v1}, Landroidx/compose/runtime/OooO;->OooO0OO(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ica;)Llyiahf/vczjk/ica;

    move-result-object v4

    invoke-virtual {v4, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    iget-boolean v5, p2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    const/4 v6, 0x0

    const/4 v7, 0x1

    if-eqz v5, :cond_6

    iget-boolean v1, p0, Llyiahf/vczjk/ke7;->OooO0o:Z

    if-nez v1, :cond_2

    invoke-interface {v0, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    :cond_2
    check-cast v0, Llyiahf/vczjk/os6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v1

    iget-object v5, v0, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    invoke-virtual {v5, v1, v2, v6, v4}, Llyiahf/vczjk/j0a;->OooOo0(ILjava/lang/Object;ILjava/lang/Object;)Llyiahf/vczjk/w3;

    move-result-object v1

    if-nez v1, :cond_3

    goto :goto_1

    :cond_3
    new-instance v2, Llyiahf/vczjk/os6;

    iget-object v4, v1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/j0a;

    iget v0, v0, Llyiahf/vczjk/qs6;->OooOOO:I

    iget v1, v1, Llyiahf/vczjk/w3;->OooOOO0:I

    add-int/2addr v0, v1

    invoke-direct {v2, v4, v0}, Llyiahf/vczjk/qs6;-><init>(Llyiahf/vczjk/j0a;I)V

    move-object v0, v2

    :cond_4
    :goto_1
    iput-boolean v7, p2, Llyiahf/vczjk/zf1;->Oooo0:Z

    :cond_5
    move v1, v6

    goto :goto_5

    :cond_6
    iget-object v5, p2, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iget v8, v5, Llyiahf/vczjk/is8;->OooO0oO:I

    iget-object v9, v5, Llyiahf/vczjk/is8;->OooO0O0:[I

    invoke-virtual {v5, v9, v8}, Llyiahf/vczjk/is8;->OooO0O0([II)Ljava/lang/Object;

    move-result-object v5

    const-string v8, "null cannot be cast to non-null type androidx.compose.runtime.PersistentCompositionLocalMap"

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v5, Llyiahf/vczjk/ps6;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-eqz v8, :cond_7

    if-nez v1, :cond_8

    :cond_7
    iget-boolean v8, p0, Llyiahf/vczjk/ke7;->OooO0o:Z

    if-nez v8, :cond_b

    invoke-interface {v0, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_8

    goto :goto_3

    :cond_8
    if-eqz v1, :cond_9

    iget-boolean v1, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    if-nez v1, :cond_9

    goto :goto_2

    :cond_9
    iget-boolean v1, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    if-eqz v1, :cond_a

    goto :goto_4

    :cond_a
    :goto_2
    move-object v0, v5

    goto :goto_4

    :cond_b
    :goto_3
    check-cast v0, Llyiahf/vczjk/os6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v1

    iget-object v8, v0, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    invoke-virtual {v8, v1, v2, v6, v4}, Llyiahf/vczjk/j0a;->OooOo0(ILjava/lang/Object;ILjava/lang/Object;)Llyiahf/vczjk/w3;

    move-result-object v1

    if-nez v1, :cond_c

    goto :goto_4

    :cond_c
    new-instance v2, Llyiahf/vczjk/os6;

    iget-object v4, v1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/j0a;

    iget v0, v0, Llyiahf/vczjk/qs6;->OooOOO:I

    iget v1, v1, Llyiahf/vczjk/w3;->OooOOO0:I

    add-int/2addr v0, v1

    invoke-direct {v2, v4, v0}, Llyiahf/vczjk/qs6;-><init>(Llyiahf/vczjk/j0a;I)V

    move-object v0, v2

    :goto_4
    iget-boolean v1, p2, Llyiahf/vczjk/zf1;->OooOo:Z

    if-nez v1, :cond_d

    if-eq v5, v0, :cond_5

    :cond_d
    move v1, v7

    :goto_5
    if-eqz v1, :cond_e

    iget-boolean v2, p2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_e

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->Oooo000(Llyiahf/vczjk/ps6;)V

    :cond_e
    iget-boolean v2, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    iget-object v4, p2, Llyiahf/vczjk/zf1;->OooOo0o:Llyiahf/vczjk/c24;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/c24;->OooO0OO(I)V

    iput-boolean v1, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    iput-object v0, p2, Llyiahf/vczjk/zf1;->Oooo0O0:Llyiahf/vczjk/ps6;

    sget-object v1, Llyiahf/vczjk/ag1;->OooO0OO:Llyiahf/vczjk/sc6;

    const/16 v2, 0xca

    invoke-virtual {p2, v2, v1, v6, v0}, Llyiahf/vczjk/zf1;->Oooo0oo(ILjava/lang/Object;ILjava/lang/Object;)V

    shr-int/lit8 v0, p3, 0x3

    and-int/lit8 v0, v0, 0xe

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4}, Llyiahf/vczjk/c24;->OooO0O0()I

    move-result v0

    if-eqz v0, :cond_f

    move v6, v7

    :cond_f
    iput-boolean v6, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    iput-object v3, p2, Llyiahf/vczjk/zf1;->Oooo0O0:Llyiahf/vczjk/ps6;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_10

    new-instance v0, Llyiahf/vczjk/wg1;

    invoke-direct {v0, p0, p1, p3}, Llyiahf/vczjk/wg1;-><init>(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;I)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_10
    return-void
.end method

.method public static final OooO0O0([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 7

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x52e5dee3

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ag1;->OooO0O0:Llyiahf/vczjk/sc6;

    const/16 v2, 0xc9

    invoke-virtual {p2, v2, v1}, Llyiahf/vczjk/zf1;->OoooO00(ILlyiahf/vczjk/sc6;)V

    iget-boolean v1, p2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    sget-object v1, Llyiahf/vczjk/os6;->OooOOOo:Llyiahf/vczjk/os6;

    invoke-static {p0, v0, v1}, Llyiahf/vczjk/u34;->o00O0O([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ps6;Llyiahf/vczjk/ps6;)Llyiahf/vczjk/os6;

    move-result-object v1

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/zf1;->OooooO0(Llyiahf/vczjk/ps6;Llyiahf/vczjk/os6;)Llyiahf/vczjk/os6;

    move-result-object v0

    iput-boolean v3, p2, Llyiahf/vczjk/zf1;->Oooo0:Z

    :cond_0
    :goto_0
    move v1, v2

    goto :goto_2

    :cond_1
    iget-object v1, p2, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iget v4, v1, Llyiahf/vczjk/is8;->OooO0oO:I

    invoke-virtual {v1, v4, v2}, Llyiahf/vczjk/is8;->OooO0oO(II)Ljava/lang/Object;

    move-result-object v1

    const-string v4, "null cannot be cast to non-null type androidx.compose.runtime.PersistentCompositionLocalMap"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/ps6;

    iget-object v5, p2, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iget v6, v5, Llyiahf/vczjk/is8;->OooO0oO:I

    invoke-virtual {v5, v6, v3}, Llyiahf/vczjk/is8;->OooO0oO(II)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v5, Llyiahf/vczjk/ps6;

    invoke-static {p0, v0, v5}, Llyiahf/vczjk/u34;->o00O0O([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ps6;Llyiahf/vczjk/ps6;)Llyiahf/vczjk/os6;

    move-result-object v4

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-eqz v6, :cond_3

    iget-boolean v6, p2, Llyiahf/vczjk/zf1;->OooOo:Z

    if-nez v6, :cond_3

    invoke-virtual {v5, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_2

    goto :goto_1

    :cond_2
    iget v0, p2, Llyiahf/vczjk/zf1;->OooOO0O:I

    iget-object v4, p2, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    invoke-virtual {v4}, Llyiahf/vczjk/is8;->OooOOOo()I

    move-result v4

    add-int/2addr v4, v0

    iput v4, p2, Llyiahf/vczjk/zf1;->OooOO0O:I

    move-object v0, v1

    goto :goto_0

    :cond_3
    :goto_1
    invoke-virtual {p2, v0, v4}, Llyiahf/vczjk/zf1;->OooooO0(Llyiahf/vczjk/ps6;Llyiahf/vczjk/os6;)Llyiahf/vczjk/os6;

    move-result-object v0

    iget-boolean v4, p2, Llyiahf/vczjk/zf1;->OooOo:Z

    if-nez v4, :cond_4

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    :cond_4
    move v1, v3

    :goto_2
    if-eqz v1, :cond_5

    iget-boolean v4, p2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_5

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->Oooo000(Llyiahf/vczjk/ps6;)V

    :cond_5
    iget-boolean v4, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    iget-object v5, p2, Llyiahf/vczjk/zf1;->OooOo0o:Llyiahf/vczjk/c24;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/c24;->OooO0OO(I)V

    iput-boolean v1, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    iput-object v0, p2, Llyiahf/vczjk/zf1;->Oooo0O0:Llyiahf/vczjk/ps6;

    sget-object v1, Llyiahf/vczjk/ag1;->OooO0OO:Llyiahf/vczjk/sc6;

    const/16 v4, 0xca

    invoke-virtual {p2, v4, v1, v2, v0}, Llyiahf/vczjk/zf1;->Oooo0oo(ILjava/lang/Object;ILjava/lang/Object;)V

    shr-int/lit8 v0, p3, 0x3

    and-int/lit8 v0, v0, 0xe

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v5}, Llyiahf/vczjk/c24;->OooO0O0()I

    move-result v0

    if-eqz v0, :cond_6

    move v2, v3

    :cond_6
    iput-boolean v2, p2, Llyiahf/vczjk/zf1;->OooOo0O:Z

    const/4 v0, 0x0

    iput-object v0, p2, Llyiahf/vczjk/zf1;->Oooo0O0:Llyiahf/vczjk/ps6;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_7

    new-instance v0, Llyiahf/vczjk/vg1;

    invoke-direct {v0, p0, p1, p3}, Llyiahf/vczjk/vg1;-><init>([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;I)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;Ljava/util/List;Llyiahf/vczjk/rf1;I)V
    .locals 22

    move-object/from16 v5, p4

    move/from16 v6, p6

    const-string v0, "chartItems"

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v0, p5

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, 0x7956cc

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    or-int/lit16 v1, v6, 0x2c30

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    const/high16 v2, 0x20000

    goto :goto_0

    :cond_0
    const/high16 v2, 0x10000

    :goto_0
    or-int/2addr v1, v2

    const v2, 0x12493

    and-int/2addr v1, v2

    const v2, 0x12492

    if-ne v1, v2, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v2, p1

    move/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v18, v0

    goto/16 :goto_4

    :cond_2
    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v6, 0x1

    if-eqz v1, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v2, p1

    move/from16 v1, p2

    move-object/from16 v3, p3

    goto :goto_3

    :cond_4
    :goto_2
    const/4 v1, 0x2

    int-to-float v1, v1

    new-instance v2, Llyiahf/vczjk/di6;

    invoke-direct {v2, v1, v1, v1, v1}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    const/16 v1, 0xc

    int-to-float v1, v1

    sget-object v3, Llyiahf/vczjk/uv7;->OooO00o:Llyiahf/vczjk/tv7;

    :goto_3
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-static {v5}, Llyiahf/vczjk/mc4;->Ooooo0o(Ljava/util/List;)Ljava/util/ArrayList;

    move-result-object v4

    sget-object v12, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    new-instance v7, Llyiahf/vczjk/zj3;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    const v8, -0x48fade91

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    const/4 v10, 0x0

    or-int/2addr v8, v9

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v8, :cond_5

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v8, :cond_6

    :cond_5
    new-instance v9, Llyiahf/vczjk/px4;

    invoke-direct {v9, v4, v2, v1, v3}, Llyiahf/vczjk/px4;-><init>(Ljava/util/ArrayList;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;)V

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object/from16 v17, v9

    check-cast v17, Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v14, 0x0

    const v19, 0x1b0030

    const/16 v20, 0x0

    const/16 v21, 0x39c

    move-object v13, v12

    move-object/from16 v8, p0

    move-object/from16 v18, v0

    invoke-static/range {v7 .. v21}, Llyiahf/vczjk/yi4;->OooOOO0(Llyiahf/vczjk/ak3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;III)V

    move-object v4, v3

    move v3, v1

    :goto_4
    invoke-virtual/range {v18 .. v18}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v7

    if-eqz v7, :cond_7

    new-instance v0, Llyiahf/vczjk/qx4;

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/qx4;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;Ljava/util/List;I)V

    iput-object v0, v7, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method

.method public static final OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;
    .locals 1

    new-instance v0, Llyiahf/vczjk/s29;

    if-nez p0, :cond_0

    sget-object p0, Llyiahf/vczjk/bua;->OooO0Oo:Llyiahf/vczjk/h87;

    :cond_0
    invoke-direct {v0, p0}, Llyiahf/vczjk/s29;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method

.method public static final OooO0o([BI[BII)Z
    .locals 4

    const-string v0, "a"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    if-ge v1, p4, :cond_1

    add-int v2, v1, p1

    aget-byte v2, p0, v2

    add-int v3, v1, p3

    aget-byte v3, p2, v3

    if-eq v2, v3, :cond_0

    return v0

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    const/4 p0, 0x1

    return p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/ib6;Llyiahf/vczjk/rf1;I)V
    .locals 33

    move-object/from16 v0, p0

    const-string v2, "item"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v6, p1

    check-cast v6, Llyiahf/vczjk/zf1;

    const v2, 0x2210b153

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    const/4 v9, 0x2

    if-eqz v2, :cond_0

    const/4 v2, 0x4

    goto :goto_0

    :cond_0
    move v2, v9

    :goto_0
    or-int v2, p2, v2

    const/4 v10, 0x3

    and-int/2addr v2, v10

    if-ne v2, v9, :cond_2

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_2
    :goto_1
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v3, 0x10

    int-to-float v11, v3

    const/4 v12, 0x0

    invoke-static {v2, v11, v12, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    sget-object v5, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    const/16 v7, 0x30

    invoke-static {v5, v4, v6, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    iget v5, v6, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v6, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_3

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_3
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v6, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v6, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_4

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_5

    :cond_4
    invoke-static {v5, v6, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v6, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v4, 0xfa

    int-to-float v4, v4

    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    iget-object v3, v0, Llyiahf/vczjk/ib6;->OooO0OO:Ljava/lang/String;

    const/4 v5, 0x0

    const/16 v7, 0x30

    const/4 v8, 0x4

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/rs;->OooO0OO(Ljava/lang/String;Llyiahf/vczjk/kl5;ILlyiahf/vczjk/rf1;II)V

    iget v3, v0, Llyiahf/vczjk/ib6;->OooO00o:I

    invoke-static {v3, v6}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/n6a;

    iget-object v13, v5, Llyiahf/vczjk/n6a;->OooO0oO:Llyiahf/vczjk/rn9;

    sget-object v18, Llyiahf/vczjk/ib3;->OooOo0o:Llyiahf/vczjk/ib3;

    const/16 v25, 0x0

    const/16 v26, 0x0

    const-wide/16 v14, 0x0

    const-wide/16 v16, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const-wide/16 v21, 0x0

    const-wide/16 v23, 0x0

    const v27, 0xfffffb

    invoke-static/range {v13 .. v27}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v21

    move-object v5, v4

    invoke-static {v2, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v7, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v6, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/x21;

    iget-wide v13, v8, Llyiahf/vczjk/x21;->OooOOo0:J

    move-object v8, v5

    move-object/from16 v22, v6

    move-wide v5, v13

    new-instance v13, Llyiahf/vczjk/ch9;

    invoke-direct {v13, v10}, Llyiahf/vczjk/ch9;-><init>(I)V

    const/16 v20, 0x0

    const/16 v23, 0x30

    move-object v14, v7

    move-object v10, v8

    const-wide/16 v7, 0x0

    move v15, v9

    const/4 v9, 0x0

    move-object/from16 v16, v10

    const/4 v10, 0x0

    move/from16 v17, v11

    move/from16 v18, v12

    const-wide/16 v11, 0x0

    move-object/from16 v24, v14

    move/from16 v19, v15

    const-wide/16 v14, 0x0

    move-object/from16 v25, v16

    const/16 v16, 0x0

    move/from16 v26, v17

    const/16 v17, 0x0

    move/from16 v27, v18

    const/16 v18, 0x0

    move/from16 v28, v19

    const/16 v19, 0x0

    move-object/from16 v29, v24

    const/16 v24, 0x0

    move-object/from16 v30, v25

    const v25, 0x1fbf8

    move/from16 v31, v26

    move-object/from16 v32, v29

    move-object/from16 v1, v30

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v6, v22

    iget v3, v0, Llyiahf/vczjk/ib6;->OooO0O0:I

    invoke-static {v3, v6}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v1, v1, Llyiahf/vczjk/n6a;->OooOO0O:Llyiahf/vczjk/rn9;

    move/from16 v4, v31

    const/4 v5, 0x0

    const/4 v15, 0x2

    invoke-static {v2, v4, v5, v15}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    move-object/from16 v14, v32

    invoke-virtual {v6, v14}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/x21;

    iget-wide v7, v2, Llyiahf/vczjk/x21;->OooOOo0:J

    new-instance v13, Llyiahf/vczjk/ch9;

    const/4 v2, 0x5

    invoke-direct {v13, v2}, Llyiahf/vczjk/ch9;-><init>(I)V

    const/16 v20, 0x0

    const/16 v23, 0x30

    move-object/from16 v22, v6

    move-wide v5, v7

    const-wide/16 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v24, 0x0

    const v25, 0x1fbf8

    move-object/from16 v21, v1

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v6, v22

    const/4 v1, 0x1

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v1

    if-eqz v1, :cond_6

    new-instance v2, Llyiahf/vczjk/sj5;

    const/4 v3, 0x3

    move/from16 v4, p2

    invoke-direct {v2, v4, v3, v0}, Llyiahf/vczjk/sj5;-><init>(IILjava/lang/Object;)V

    iput-object v2, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void
.end method

.method public static OooO0oO(Landroid/content/Context;Landroid/net/Uri;)Z
    .locals 13

    const/4 v1, 0x2

    invoke-virtual {p0, p1, v1}, Landroid/content/Context;->checkCallingOrSelfUriPermission(Landroid/net/Uri;I)I

    move-result v0

    const/4 v2, 0x0

    if-eqz v0, :cond_0

    goto/16 :goto_3

    :cond_0
    const-string v0, "mime_type"

    invoke-static {p0, p1, v0}, Llyiahf/vczjk/r02;->OooOoo(Landroid/content/Context;Landroid/net/Uri;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    const-string v0, "flags"

    int-to-long v4, v2

    const-string v6, "Failed query: "

    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v7

    const/4 p0, 0x0

    :try_start_0
    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v9

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v10, 0x0

    move-object v8, p1

    invoke-virtual/range {v7 .. v12}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-interface {p0, v2}, Landroid/database/Cursor;->isNull(I)Z

    move-result p1

    if-nez p1, :cond_1

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_1
    :goto_0
    invoke-static {p0}, Llyiahf/vczjk/r02;->OooO(Landroid/database/Cursor;)V

    goto :goto_1

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto :goto_4

    :catch_0
    move-exception v0

    move-object p1, v0

    :try_start_1
    const-string v0, "DocumentFile"

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :goto_1
    long-to-int p0, v4

    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p1

    if-eqz p1, :cond_2

    goto :goto_3

    :cond_2
    and-int/lit8 p1, p0, 0x4

    if-eqz p1, :cond_3

    goto :goto_2

    :cond_3
    const-string p1, "vnd.android.document/directory"

    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_4

    and-int/lit8 p1, p0, 0x8

    if-eqz p1, :cond_4

    goto :goto_2

    :cond_4
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p1

    if-nez p1, :cond_5

    and-int/2addr p0, v1

    if-eqz p0, :cond_5

    :goto_2
    const/4 p0, 0x1

    return p0

    :cond_5
    :goto_3
    return v2

    :goto_4
    invoke-static {p0}, Llyiahf/vczjk/r02;->OooO(Landroid/database/Cursor;)V

    throw p1
.end method

.method public static final OooO0oo(JJJ)V
    .locals 4

    or-long v0, p2, p4

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-ltz v0, :cond_0

    cmp-long v0, p2, p0

    if-gtz v0, :cond_0

    sub-long v0, p0, p2

    cmp-long v0, v0, p4

    if-ltz v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/ArrayIndexOutOfBoundsException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "size="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0, p1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string p0, " offset="

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string p0, " byteCount="

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p4, p5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;
    .locals 6

    const/4 v0, 0x1

    and-int/lit8 v1, p1, 0x1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move v1, v0

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    and-int/lit8 p1, p1, 0x2

    if-eqz p1, :cond_1

    goto :goto_1

    :cond_1
    move v0, v2

    :goto_1
    const-string p1, "<this>"

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    if-eqz v0, :cond_3

    instance-of v0, p0, Llyiahf/vczjk/il1;

    if-eqz v0, :cond_2

    const-string v0, "<init>"

    goto :goto_2

    :cond_2
    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/w02;

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v2, "asString(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_2
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_3
    const-string v0, "("

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p0}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/tb1;->Oooo0oo:Llyiahf/vczjk/tb1;

    const-string v3, "getType(...)"

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/q4a;->OooOO0O:Llyiahf/vczjk/q4a;

    invoke-static {v0, v4, v2}, Llyiahf/vczjk/cp7;->Oooo00O(Llyiahf/vczjk/uk4;Llyiahf/vczjk/q4a;Llyiahf/vczjk/bf3;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/af4;

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    :cond_4
    invoke-interface {p0}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/tca;

    check-cast v4, Llyiahf/vczjk/bda;

    invoke-virtual {v4}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v5, Llyiahf/vczjk/q4a;->OooOO0O:Llyiahf/vczjk/q4a;

    invoke-static {v4, v5, v2}, Llyiahf/vczjk/cp7;->Oooo00O(Llyiahf/vczjk/uk4;Llyiahf/vczjk/q4a;Llyiahf/vczjk/bf3;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/af4;

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    goto :goto_3

    :cond_5
    const-string v0, ")"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    if-eqz v1, :cond_8

    instance-of v0, p0, Llyiahf/vczjk/il1;

    if-eqz v0, :cond_6

    goto :goto_4

    :cond_6
    invoke-interface {p0}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    sget-object v1, Llyiahf/vczjk/w09;->OooO0Oo:Llyiahf/vczjk/ic3;

    invoke-static {v0, v1}, Llyiahf/vczjk/hk4;->OooOooo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-interface {p0}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-nez v0, :cond_7

    instance-of v0, p0, Llyiahf/vczjk/va7;

    if-nez v0, :cond_7

    :goto_4
    const-string p0, "V"

    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_5

    :cond_7
    invoke-interface {p0}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/q4a;->OooOO0O:Llyiahf/vczjk/q4a;

    invoke-static {p0, v0, v2}, Llyiahf/vczjk/cp7;->Oooo00O(Llyiahf/vczjk/uk4;Llyiahf/vczjk/q4a;Llyiahf/vczjk/bf3;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/af4;

    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    :cond_8
    :goto_5
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOO0O(Llyiahf/vczjk/co0;)Ljava/lang/String;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooOOOO(Llyiahf/vczjk/v02;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    goto :goto_2

    :cond_0
    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    instance-of v2, v0, Llyiahf/vczjk/by0;

    if-eqz v2, :cond_1

    check-cast v0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_1
    move-object v0, v1

    :goto_0
    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-interface {v0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    iget-boolean v2, v2, Llyiahf/vczjk/qt5;->OooOOO:Z

    if-eqz v2, :cond_3

    goto :goto_2

    :cond_3
    invoke-interface {p0}, Llyiahf/vczjk/co0;->OooO00o()Llyiahf/vczjk/co0;

    move-result-object p0

    instance-of v2, p0, Llyiahf/vczjk/ho8;

    if-eqz v2, :cond_4

    check-cast p0, Llyiahf/vczjk/ho8;

    goto :goto_1

    :cond_4
    move-object p0, v1

    :goto_1
    if-nez p0, :cond_5

    :goto_2
    return-object v1

    :cond_5
    const/4 v1, 0x3

    invoke-static {p0, v1}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object p0

    invoke-static {v0, p0}, Llyiahf/vczjk/t51;->OoooOoO(Llyiahf/vczjk/by0;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOO0o(IIIILlyiahf/vczjk/r78;)D
    .locals 4

    int-to-double v0, p2

    int-to-double v2, p0

    div-double/2addr v0, v2

    int-to-double p2, p3

    int-to-double p0, p1

    div-double/2addr p2, p0

    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    if-eqz p0, :cond_1

    const/4 p1, 0x1

    if-ne p0, p1, :cond_0

    invoke-static {v0, v1, p2, p3}, Ljava/lang/Math;->min(DD)D

    move-result-wide p0

    return-wide p0

    :cond_0
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_1
    invoke-static {v0, v1, p2, p3}, Ljava/lang/Math;->max(DD)D

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOOO(Llyiahf/vczjk/by0;Llyiahf/vczjk/by0;)Llyiahf/vczjk/g19;
    .locals 4

    const-string v0, "from"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "to"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/by0;->OooOo00()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->size()I

    invoke-interface {p1}, Llyiahf/vczjk/by0;->OooOo00()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->size()I

    invoke-interface {p0}, Llyiahf/vczjk/by0;->OooOo00()Ljava/util/List;

    move-result-object p0

    const-string v0, "getDeclaredTypeParameters(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {p0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/t4a;

    invoke-interface {v3}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/by0;->OooOo00()Ljava/util/List;

    move-result-object p0

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Ljava/util/ArrayList;

    invoke-static {p0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/t4a;

    invoke-interface {v0}, Llyiahf/vczjk/gz0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    const-string v2, "getDefaultType(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/fu6;->OooO0oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/f19;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    invoke-static {v1, p1}, Llyiahf/vczjk/d21;->o0000Oo(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object p0

    new-instance p1, Llyiahf/vczjk/g19;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/g19;-><init>(Ljava/lang/Object;I)V

    return-object p1
.end method

.method public static OooOOO0()Llyiahf/vczjk/y05;
    .locals 2

    new-instance v0, Llyiahf/vczjk/y05;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Llyiahf/vczjk/y05;-><init>(I)V

    return-object v0
.end method

.method public static final OooOOOO(Landroid/content/Context;)Llyiahf/vczjk/ov5;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ov5;

    const-string v1, "context"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, p0}, Llyiahf/vczjk/ov5;-><init>(Landroid/content/Context;)V

    iget-object p0, v0, Llyiahf/vczjk/ov5;->OooO0O0:Llyiahf/vczjk/su5;

    iget-object v1, p0, Llyiahf/vczjk/su5;->OooOOoo:Llyiahf/vczjk/ty5;

    new-instance v2, Llyiahf/vczjk/yd1;

    invoke-direct {v2, v1}, Llyiahf/vczjk/hv5;-><init>(Llyiahf/vczjk/ty5;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ty5;->OooO00o(Llyiahf/vczjk/sy5;)V

    iget-object v1, p0, Llyiahf/vczjk/su5;->OooOOoo:Llyiahf/vczjk/ty5;

    new-instance v2, Llyiahf/vczjk/ae1;

    invoke-direct {v2}, Llyiahf/vczjk/ae1;-><init>()V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ty5;->OooO00o(Llyiahf/vczjk/sy5;)V

    iget-object p0, p0, Llyiahf/vczjk/su5;->OooOOoo:Llyiahf/vczjk/ty5;

    new-instance v1, Llyiahf/vczjk/za2;

    invoke-direct {v1}, Llyiahf/vczjk/za2;-><init>()V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ty5;->OooO00o(Llyiahf/vczjk/sy5;)V

    return-object v0
.end method

.method public static OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/dha;
    .locals 3

    const-string v0, "Cannot create an instance of "

    const/4 v1, 0x0

    :try_start_0
    invoke-virtual {p0, v1}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v1, Llyiahf/vczjk/dha;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/InstantiationException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v1

    :catch_0
    move-exception v1

    goto :goto_0

    :catch_1
    move-exception v1

    goto :goto_1

    :catch_2
    move-exception v1

    goto :goto_2

    :goto_0
    new-instance v2, Ljava/lang/RuntimeException;

    invoke-static {p0, v0}, Llyiahf/vczjk/ii5;->OooO0oO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v2, p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2

    :goto_1
    new-instance v2, Ljava/lang/RuntimeException;

    invoke-static {p0, v0}, Llyiahf/vczjk/ii5;->OooO0oO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v2, p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2

    :goto_2
    new-instance v2, Ljava/lang/RuntimeException;

    invoke-static {p0, v0}, Llyiahf/vczjk/ii5;->OooO0oO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v2, p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2
.end method

.method public static final OooOOo(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/gz0;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/cp7;->OooOO0O:Llyiahf/vczjk/mm3;

    invoke-interface {p0, v0}, Llyiahf/vczjk/cm5;->OoooOoo(Llyiahf/vczjk/mm3;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_5

    iget-object v0, p1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-interface {p0, v0}, Llyiahf/vczjk/cm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object p0

    iget-object p1, p1, Llyiahf/vczjk/hy0;->OooO0O0:Llyiahf/vczjk/hc3;

    iget-object p1, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/ic3;->OooO0o0(Llyiahf/vczjk/ic3;)Ljava/util/List;

    move-result-object p1

    check-cast p0, Llyiahf/vczjk/hw4;

    iget-object p0, p0, Llyiahf/vczjk/hw4;->OooOo0O:Llyiahf/vczjk/pw4;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qt5;

    sget-object v1, Llyiahf/vczjk/h16;->OooOOoo:Llyiahf/vczjk/h16;

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/pw4;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object p0

    const/4 v0, 0x0

    if-nez p0, :cond_0

    goto :goto_2

    :cond_0
    const/4 v1, 0x1

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v2

    invoke-interface {p1, v1, v2}, Ljava/util/List;->subList(II)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qt5;

    instance-of v2, p0, Llyiahf/vczjk/by0;

    if-nez v2, :cond_1

    goto :goto_2

    :cond_1
    check-cast p0, Llyiahf/vczjk/by0;

    invoke-interface {p0}, Llyiahf/vczjk/by0;->o0ooOO0()Llyiahf/vczjk/jg5;

    move-result-object p0

    sget-object v2, Llyiahf/vczjk/h16;->OooOOoo:Llyiahf/vczjk/h16;

    invoke-interface {p0, v1, v2}, Llyiahf/vczjk/mr7;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of v1, p0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_2

    check-cast p0, Llyiahf/vczjk/by0;

    goto :goto_1

    :cond_2
    move-object p0, v0

    :goto_1
    if-eqz p0, :cond_3

    goto :goto_0

    :cond_3
    :goto_2
    return-object v0

    :cond_4
    return-object p0

    :cond_5
    new-instance p0, Ljava/lang/ClassCastException;

    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    throw p0
.end method

.method public static final OooOOo0(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Llyiahf/vczjk/r02;->OooOOo(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of p1, p0, Llyiahf/vczjk/by0;

    if-eqz p1, :cond_0

    check-cast p0, Llyiahf/vczjk/by0;

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooOOoo(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/by0;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "notFoundClasses"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Llyiahf/vczjk/r02;->OooOOo0(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object p0

    if-eqz p0, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/h13;->OooOOO:Llyiahf/vczjk/h13;

    invoke-static {p1, p0}, Llyiahf/vczjk/ag8;->Oooo0OO(Ljava/lang/Object;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/wf8;

    move-result-object p0

    sget-object v0, Llyiahf/vczjk/g13;->OooOOO:Llyiahf/vczjk/g13;

    invoke-static {p0, v0}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object p0

    invoke-virtual {p2, p1, p0}, Llyiahf/vczjk/ld9;->OoooO(Llyiahf/vczjk/hy0;Ljava/util/List;)Llyiahf/vczjk/by0;

    move-result-object p0

    return-object p0
.end method

.method public static OooOo(Ljava/lang/Object;)Ljava/util/List;
    .locals 1

    invoke-static {p0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p0

    const-string v0, "singletonList(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final OooOo0(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooOo00(Llyiahf/vczjk/no0;)Llyiahf/vczjk/qo0;
    .locals 3

    new-instance v0, Llyiahf/vczjk/mo0;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/or7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/mo0;->OooO0OO:Llyiahf/vczjk/or7;

    new-instance v1, Llyiahf/vczjk/qo0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/qo0;-><init>(Llyiahf/vczjk/mo0;)V

    iput-object v1, v0, Llyiahf/vczjk/mo0;->OooO0O0:Llyiahf/vczjk/qo0;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    iput-object v2, v0, Llyiahf/vczjk/mo0;->OooO00o:Ljava/lang/Object;

    :try_start_0
    invoke-interface {p0, v0}, Llyiahf/vczjk/no0;->OooO0O0(Llyiahf/vczjk/mo0;)Ljava/lang/Object;

    move-result-object p0

    if-eqz p0, :cond_0

    iput-object p0, v0, Llyiahf/vczjk/mo0;->OooO00o:Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v1

    :catch_0
    move-exception p0

    iget-object v0, v1, Llyiahf/vczjk/qo0;->OooOOO:Llyiahf/vczjk/po0;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/o0o0Oo;->OooO(Ljava/lang/Throwable;)Z

    :cond_0
    return-object v1
.end method

.method public static final OooOo0O(Ljava/lang/Throwable;Llyiahf/vczjk/or1;)V
    .locals 4

    sget-object v0, Llyiahf/vczjk/sr1;->OooO00o:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rr1;

    :try_start_0
    invoke-interface {v1, p0}, Llyiahf/vczjk/rr1;->OoooOoo(Ljava/lang/Throwable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    if-ne p0, v1, :cond_0

    move-object v2, p0

    goto :goto_1

    :cond_0
    new-instance v2, Ljava/lang/RuntimeException;

    const-string v3, "Exception while trying to handle coroutine exception"

    invoke-direct {v2, v3, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-static {v2, p0}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v3

    invoke-interface {v3, v1, v2}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    goto :goto_0

    :cond_1
    :try_start_1
    new-instance v0, Llyiahf/vczjk/z92;

    invoke-direct {v0, p1}, Llyiahf/vczjk/z92;-><init>(Llyiahf/vczjk/or1;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v0

    invoke-interface {v0, p1, p0}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static final OooOo0o(Llyiahf/vczjk/ro4;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-eqz v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    iget-object p0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-boolean p0, p0, Llyiahf/vczjk/vo4;->OooO0O0:Z

    if-eqz p0, :cond_2

    :cond_1
    const/4 p0, 0x1

    return p0

    :cond_2
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOoo(Landroid/content/Context;Landroid/net/Uri;Ljava/lang/String;)Ljava/lang/String;
    .locals 9

    const-string v1, "Failed query: "

    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v2

    const/4 p0, 0x0

    :try_start_0
    filled-new-array {p2}, [Ljava/lang/String;

    move-result-object v4

    const/4 v7, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v3, p1

    invoke-virtual/range {v2 .. v7}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    invoke-interface {p1}, Landroid/database/Cursor;->moveToFirst()Z

    move-result p2

    if-eqz p2, :cond_0

    const/4 p2, 0x0

    invoke-interface {p1, p2}, Landroid/database/Cursor;->isNull(I)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-interface {p1, p2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object p0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO(Landroid/database/Cursor;)V

    return-object p0

    :catchall_0
    move-exception v0

    move-object p0, v0

    goto :goto_1

    :catch_0
    move-exception v0

    move-object p2, v0

    goto :goto_0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO(Landroid/database/Cursor;)V

    return-object p0

    :catchall_1
    move-exception v0

    move-object p1, v0

    move-object v8, p1

    move-object p1, p0

    move-object p0, v8

    goto :goto_1

    :catch_1
    move-exception v0

    move-object p2, v0

    move-object p1, p0

    :goto_0
    :try_start_2
    const-string v0, "DocumentFile"

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-static {v0, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO(Landroid/database/Cursor;)V

    return-object p0

    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO(Landroid/database/Cursor;)V

    throw p0
.end method

.method public static OooOoo0(Landroid/animation/AnimatorSet;Ljava/util/ArrayList;)V
    .locals 10

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v0

    const-wide/16 v1, 0x0

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v0, :cond_0

    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/animation/Animator;

    invoke-virtual {v5}, Landroid/animation/Animator;->getStartDelay()J

    move-result-wide v6

    invoke-virtual {v5}, Landroid/animation/Animator;->getDuration()J

    move-result-wide v8

    add-long/2addr v8, v6

    invoke-static {v1, v2, v8, v9}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v1

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    filled-new-array {v3, v3}, [I

    move-result-object v0

    invoke-static {v0}, Landroid/animation/ValueAnimator;->ofInt([I)Landroid/animation/ValueAnimator;

    move-result-object v0

    invoke-virtual {v0, v1, v2}, Landroid/animation/Animator;->setDuration(J)Landroid/animation/Animator;

    invoke-virtual {p1, v3, v0}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    invoke-virtual {p0, p1}, Landroid/animation/AnimatorSet;->playTogether(Ljava/util/Collection;)V

    return-void
.end method

.method public static final OooOooO(Llyiahf/vczjk/yo1;)Ljava/lang/String;
    .locals 3

    instance-of v0, p0, Llyiahf/vczjk/fc2;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/fc2;

    invoke-virtual {p0}, Llyiahf/vczjk/fc2;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    const/16 v0, 0x40

    :try_start_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Llyiahf/vczjk/r02;->OooOo0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    invoke-static {v1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v1

    :goto_0
    invoke-static {v1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v2

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Llyiahf/vczjk/r02;->OooOo0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    :goto_1
    check-cast v1, Ljava/lang/String;

    return-object v1
.end method

.method public static final OooOooo(Llyiahf/vczjk/gl9;)Landroid/view/inputmethod/ExtractedText;
    .locals 4

    new-instance v0, Landroid/view/inputmethod/ExtractedText;

    invoke-direct {v0}, Landroid/view/inputmethod/ExtractedText;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iput-object v1, v0, Landroid/view/inputmethod/ExtractedText;->text:Ljava/lang/CharSequence;

    const/4 v2, 0x0

    iput v2, v0, Landroid/view/inputmethod/ExtractedText;->startOffset:I

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->partialEndOffset:I

    const/4 v1, -0x1

    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->partialStartOffset:I

    iget-wide v1, p0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result v3

    iput v3, v0, Landroid/view/inputmethod/ExtractedText;->selectionStart:I

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->selectionEnd:I

    iget-object p0, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object p0, p0, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    const/16 v1, 0xa

    invoke-static {p0, v1}, Llyiahf/vczjk/z69;->Oooo0o0(Ljava/lang/CharSequence;C)Z

    move-result p0

    xor-int/lit8 p0, p0, 0x1

    iput p0, v0, Landroid/view/inputmethod/ExtractedText;->flags:I

    return-object v0
.end method

.method public static final Oooo0(II)V
    .locals 4

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-lez p0, :cond_0

    if-lez p1, :cond_0

    move v2, v1

    goto :goto_0

    :cond_0
    move v2, v0

    :goto_0
    if-nez v2, :cond_1

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "both minLines "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, " and maxLines "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, " must be greater than zero"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :cond_1
    if-gt p0, p1, :cond_2

    move v0, v1

    :cond_2
    if-nez v0, :cond_3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "minLines "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p0, " must be less than or equal to maxLines "

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :cond_3
    return-void
.end method

.method public static final Oooo000(I)Ljava/lang/String;
    .locals 12

    const/4 v0, 0x1

    const/4 v1, 0x0

    const/4 v2, 0x4

    const/16 v3, 0x8

    if-nez p0, :cond_0

    const-string p0, "0"

    return-object p0

    :cond_0
    sget-object v4, Llyiahf/vczjk/sb;->OooO00o:[C

    shr-int/lit8 v5, p0, 0x1c

    and-int/lit8 v5, v5, 0xf

    aget-char v5, v4, v5

    shr-int/lit8 v6, p0, 0x18

    and-int/lit8 v6, v6, 0xf

    aget-char v6, v4, v6

    shr-int/lit8 v7, p0, 0x14

    and-int/lit8 v7, v7, 0xf

    aget-char v7, v4, v7

    shr-int/lit8 v8, p0, 0x10

    and-int/lit8 v8, v8, 0xf

    aget-char v8, v4, v8

    shr-int/lit8 v9, p0, 0xc

    and-int/lit8 v9, v9, 0xf

    aget-char v9, v4, v9

    shr-int/lit8 v10, p0, 0x8

    and-int/lit8 v10, v10, 0xf

    aget-char v10, v4, v10

    shr-int/lit8 v11, p0, 0x4

    and-int/lit8 v11, v11, 0xf

    aget-char v11, v4, v11

    and-int/lit8 p0, p0, 0xf

    aget-char p0, v4, p0

    new-array v4, v3, [C

    aput-char v5, v4, v1

    aput-char v6, v4, v0

    const/4 v5, 0x2

    aput-char v7, v4, v5

    const/4 v5, 0x3

    aput-char v8, v4, v5

    aput-char v9, v4, v2

    const/4 v2, 0x5

    aput-char v10, v4, v2

    const/4 v2, 0x6

    aput-char v11, v4, v2

    const/4 v2, 0x7

    aput-char p0, v4, v2

    :goto_0
    if-ge v1, v3, :cond_1

    aget-char p0, v4, v1

    const/16 v2, 0x30

    if-ne p0, v2, :cond_1

    add-int/2addr v1, v0

    goto :goto_0

    :cond_1
    const-string p0, "startIndex: "

    if-ltz v1, :cond_3

    if-gt v1, v3, :cond_2

    new-instance p0, Ljava/lang/String;

    sub-int/2addr v3, v1

    invoke-direct {p0, v4, v1, v3}, Ljava/lang/String;-><init>([CII)V

    return-object p0

    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v2, " > endIndex: 8"

    invoke-static {v1, p0, v2}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_3
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    const-string v2, ", endIndex: 8, size: 8"

    invoke-static {v1, p0, v2}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static Oooo00O(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;
    .locals 4

    const-string v0, "shortName"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/hc3;

    new-instance v1, Llyiahf/vczjk/ic3;

    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v2

    const-string v3, "asString(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/hc3;->OooO0OO:Llyiahf/vczjk/hc3;

    iget-object v3, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-direct {v1, v2, v3, p0}, Llyiahf/vczjk/ic3;-><init>(Ljava/lang/String;Llyiahf/vczjk/ic3;Llyiahf/vczjk/qt5;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Llyiahf/vczjk/ic3;)V

    return-object v0
.end method

.method public static Oooo0O0(Llyiahf/vczjk/ol0;IJ)V
    .locals 2

    invoke-static {p2, p3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    move-result v0

    rsub-int/lit8 v0, v0, 0x40

    if-nez v0, :cond_0

    const/4 v0, 0x1

    :cond_0
    add-int/lit8 v0, v0, 0x7

    shr-int/lit8 v0, v0, 0x3

    mul-int/lit8 v1, v0, 0x8

    rsub-int/lit8 v1, v1, 0x40

    shr-long/2addr p2, v1

    add-int/lit8 v1, v0, -0x1

    shl-int/lit8 v1, v1, 0x5

    or-int/2addr p1, v1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ol0;->OooO(I)V

    :goto_0
    if-lez v0, :cond_1

    long-to-int p1, p2

    int-to-byte p1, p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ol0;->OooO(I)V

    const/16 p1, 0x8

    shr-long/2addr p2, p1

    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public static Oooo0OO(Llyiahf/vczjk/ol0;IJ)V
    .locals 2

    invoke-static {p2, p3}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    move-result v0

    rsub-int/lit8 v0, v0, 0x40

    if-nez v0, :cond_0

    const/4 v0, 0x1

    :cond_0
    add-int/lit8 v0, v0, 0x7

    shr-int/lit8 v0, v0, 0x3

    add-int/lit8 v1, v0, -0x1

    shl-int/lit8 v1, v1, 0x5

    or-int/2addr p1, v1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ol0;->OooO(I)V

    :goto_0
    if-lez v0, :cond_1

    long-to-int p1, p2

    int-to-byte p1, p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ol0;->OooO(I)V

    const/16 p1, 0x8

    shr-long/2addr p2, p1

    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method


# virtual methods
.method public OooOoO()V
    .locals 0

    return-void
.end method

.method public OooOoO0(ILjava/lang/CharSequence;)V
    .locals 0

    return-void
.end method

.method public OooOoOO(Llyiahf/vczjk/mc0;)V
    .locals 0

    return-void
.end method

.method public abstract Oooo00o(ILjava/io/StringWriter;Ljava/lang/String;)I
.end method
