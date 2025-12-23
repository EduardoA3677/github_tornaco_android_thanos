.class public final Llyiahf/vczjk/zba;
.super Llyiahf/vczjk/rl6;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Ljava/lang/Object;

.field public final OooO0Oo:Llyiahf/vczjk/lea;

.field public final OooO0o0:Llyiahf/vczjk/pp3;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/lea;Llyiahf/vczjk/pp3;)V
    .locals 1

    const-string v0, "value"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "verificationMode"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zba;->OooO0OO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/zba;->OooO0Oo:Llyiahf/vczjk/lea;

    iput-object p3, p0, Llyiahf/vczjk/zba;->OooO0o0:Llyiahf/vczjk/pp3;

    return-void
.end method


# virtual methods
.method public final OooO0oO()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zba;->OooO0OO:Ljava/lang/Object;

    return-object v0
.end method

.method public final OooOo(Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/rl6;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zba;->OooO0OO:Ljava/lang/Object;

    invoke-interface {p2, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    if-eqz p2, :cond_0

    return-object p0

    :cond_0
    new-instance p2, Llyiahf/vczjk/qv2;

    iget-object v1, p0, Llyiahf/vczjk/zba;->OooO0o0:Llyiahf/vczjk/pp3;

    iget-object v2, p0, Llyiahf/vczjk/zba;->OooO0Oo:Llyiahf/vczjk/lea;

    invoke-direct {p2, v0, p1, v1, v2}, Llyiahf/vczjk/qv2;-><init>(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/pp3;Llyiahf/vczjk/lea;)V

    return-object p2
.end method
