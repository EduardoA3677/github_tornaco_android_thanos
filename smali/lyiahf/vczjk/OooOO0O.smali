.class public abstract Llyiahf/vczjk/OooOO0O;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/k32;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/k32;

    invoke-direct {v0}, Llyiahf/vczjk/k32;-><init>()V

    sput-object v0, Llyiahf/vczjk/OooOO0O;->OooO00o:Llyiahf/vczjk/k32;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kv3;)Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/kv3;->OooO0o0:Llyiahf/vczjk/s07;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_3

    const/4 v2, 0x1

    if-eq v0, v2, :cond_2

    const/4 v3, 0x2

    if-ne v0, v3, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/kv3;->OooOoO0:Llyiahf/vczjk/z42;

    iget-object v0, v0, Llyiahf/vczjk/z42;->OooO00o:Llyiahf/vczjk/ar8;

    if-nez v0, :cond_0

    iget-object p0, p0, Llyiahf/vczjk/kv3;->OooOo0O:Llyiahf/vczjk/ar8;

    instance-of p0, p0, Llyiahf/vczjk/mc2;

    if-eqz p0, :cond_0

    return v2

    :cond_0
    return v1

    :cond_1
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_2
    return v2

    :cond_3
    return v1
.end method
