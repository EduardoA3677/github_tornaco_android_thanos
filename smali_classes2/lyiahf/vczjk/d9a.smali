.class public final Llyiahf/vczjk/d9a;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/d9a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/d9a;

    invoke-direct {v0}, Llyiahf/vczjk/qr1;-><init>()V

    sput-object v0, Llyiahf/vczjk/d9a;->OooOOOO:Llyiahf/vczjk/d9a;

    return-void
.end method


# virtual methods
.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 2

    sget-object p1, Llyiahf/vczjk/q32;->OooOOOo:Llyiahf/vczjk/q32;

    const/4 v0, 0x1

    iget-object p1, p1, Llyiahf/vczjk/k88;->OooOOOO:Llyiahf/vczjk/wr1;

    const/4 v1, 0x0

    invoke-virtual {p1, p2, v0, v1}, Llyiahf/vczjk/wr1;->OooO0oO(Ljava/lang/Runnable;ZZ)V

    return-void
.end method

.method public final o00000oo(I)Llyiahf/vczjk/qr1;
    .locals 1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOoOO(I)V

    sget v0, Llyiahf/vczjk/xg9;->OooO0Oo:I

    if-lt p1, v0, :cond_0

    return-object p0

    :cond_0
    invoke-super {p0, p1}, Llyiahf/vczjk/qr1;->o00000oo(I)Llyiahf/vczjk/qr1;

    move-result-object p1

    return-object p1
.end method

.method public final o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 1

    sget-object p1, Llyiahf/vczjk/q32;->OooOOOo:Llyiahf/vczjk/q32;

    iget-object p1, p1, Llyiahf/vczjk/k88;->OooOOOO:Llyiahf/vczjk/wr1;

    const/4 v0, 0x1

    invoke-virtual {p1, p2, v0, v0}, Llyiahf/vczjk/wr1;->OooO0oO(Ljava/lang/Runnable;ZZ)V

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Dispatchers.IO"

    return-object v0
.end method
