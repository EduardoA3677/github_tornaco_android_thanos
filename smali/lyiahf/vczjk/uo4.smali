.class public abstract Llyiahf/vczjk/uo4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/i62;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    invoke-static {}, Llyiahf/vczjk/vc6;->OooO0o0()Llyiahf/vczjk/i62;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uo4;->OooO00o:Llyiahf/vczjk/i62;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz p0, :cond_0

    return-object p0

    :cond_0
    const-string p0, "LayoutNode should be attached to an owner"

    invoke-static {p0}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object p0

    throw p0
.end method
