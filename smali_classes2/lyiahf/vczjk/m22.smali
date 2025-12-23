.class public final Llyiahf/vczjk/m22;
.super Llyiahf/vczjk/hs2;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Executor;


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/m22;

.field public static final OooOOOo:Llyiahf/vczjk/qr1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/m22;

    invoke-direct {v0}, Llyiahf/vczjk/qr1;-><init>()V

    sput-object v0, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    sget-object v0, Llyiahf/vczjk/d9a;->OooOOOO:Llyiahf/vczjk/d9a;

    sget v1, Llyiahf/vczjk/pd9;->OooO00o:I

    const/16 v2, 0x40

    if-ge v2, v1, :cond_0

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    const/16 v2, 0xc

    const-string v3, "kotlinx.coroutines.io.parallelism"

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/eo6;->OooOoo0(IILjava/lang/String;)I

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/d9a;->o00000oo(I)Llyiahf/vczjk/qr1;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/m22;->OooOOOo:Llyiahf/vczjk/qr1;

    return-void
.end method


# virtual methods
.method public final close()V
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Cannot be invoked on Dispatchers.IO"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final execute(Ljava/lang/Runnable;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/m22;->o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final o0000()Ljava/util/concurrent/Executor;
    .locals 0

    return-object p0
.end method

.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/m22;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/qr1;->o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final o00000oo(I)Llyiahf/vczjk/qr1;
    .locals 1

    const/4 p1, 0x1

    sget-object v0, Llyiahf/vczjk/d9a;->OooOOOO:Llyiahf/vczjk/d9a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/d9a;->o00000oo(I)Llyiahf/vczjk/qr1;

    move-result-object p1

    return-object p1
.end method

.method public final o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/m22;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/qr1;->o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Dispatchers.IO"

    return-object v0
.end method
