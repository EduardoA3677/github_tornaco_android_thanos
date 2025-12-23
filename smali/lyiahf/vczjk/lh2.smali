.class public final Llyiahf/vczjk/lh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $drawerState:Llyiahf/vczjk/li2;

.field final synthetic $scope:Llyiahf/vczjk/xr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li2;Llyiahf/vczjk/xr1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lh2;->$drawerState:Llyiahf/vczjk/li2;

    iput-object p2, p0, Llyiahf/vczjk/lh2;->$scope:Llyiahf/vczjk/xr1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/lh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-object v0, v0, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    iget-object v0, v0, Llyiahf/vczjk/d9;->OooO0Oo:Llyiahf/vczjk/oe3;

    sget-object v1, Llyiahf/vczjk/ni2;->OooOOO0:Llyiahf/vczjk/ni2;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/lh2;->$scope:Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/kh2;

    iget-object v2, p0, Llyiahf/vczjk/lh2;->$drawerState:Llyiahf/vczjk/li2;

    const/4 v3, 0x0

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/kh2;-><init>(Llyiahf/vczjk/li2;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {v0, v3, v3, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_0
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0
.end method
