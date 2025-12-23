.class public final Llyiahf/vczjk/oc2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/no7;


# instance fields
.field public OooOOO:Llyiahf/vczjk/pc2;

.field public final OooOOO0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oc2;->OooOOO0:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 0

    return-void
.end method

.method public final OooO0O0()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/oc2;->OooOOO:Llyiahf/vczjk/pc2;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/pc2;->OooO00o()V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/oc2;->OooOOO:Llyiahf/vczjk/pc2;

    return-void
.end method

.method public final OooO0OO()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/c6a;->OooOo0O:Llyiahf/vczjk/qc2;

    iget-object v1, p0, Llyiahf/vczjk/oc2;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pc2;

    iput-object v0, p0, Llyiahf/vczjk/oc2;->OooOOO:Llyiahf/vczjk/pc2;

    return-void
.end method
