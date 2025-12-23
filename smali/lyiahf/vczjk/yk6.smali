.class public final Llyiahf/vczjk/yk6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $scope:Llyiahf/vczjk/xr1;

.field final synthetic $state:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/xr1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yk6;->$state:Llyiahf/vczjk/lm6;

    iput-object p2, p0, Llyiahf/vczjk/yk6;->$scope:Llyiahf/vczjk/xr1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/yk6;->$state:Llyiahf/vczjk/lm6;

    iget-object v1, p0, Llyiahf/vczjk/yk6;->$scope:Llyiahf/vczjk/xr1;

    invoke-virtual {v0}, Llyiahf/vczjk/lm6;->OooO0Oo()Z

    move-result v2

    if-eqz v2, :cond_0

    new-instance v2, Llyiahf/vczjk/bl6;

    const/4 v3, 0x0

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/bl6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {v1, v3, v3, v2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
