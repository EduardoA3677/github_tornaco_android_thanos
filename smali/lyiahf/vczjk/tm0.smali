.class public final Llyiahf/vczjk/tm0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f62;


# instance fields
.field public OooOOO:Llyiahf/vczjk/gg2;

.field public OooOOO0:Llyiahf/vczjk/qj0;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/sm2;->OooOOO0:Llyiahf/vczjk/sm2;

    iput-object v0, p0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;
    .locals 1

    new-instance v0, Llyiahf/vczjk/gg2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object p1, v0, Llyiahf/vczjk/gg2;->OooOOO0:Llyiahf/vczjk/oe3;

    iput-object v0, p0, Llyiahf/vczjk/tm0;->OooOOO:Llyiahf/vczjk/gg2;

    return-object v0
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v0}, Llyiahf/vczjk/qj0;->OooO0O0()Llyiahf/vczjk/f62;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v0}, Llyiahf/vczjk/qj0;->OooO0O0()Llyiahf/vczjk/f62;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/f62;->o000oOoO()F

    move-result v0

    return v0
.end method
