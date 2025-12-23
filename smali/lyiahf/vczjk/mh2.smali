.class public final Llyiahf/vczjk/mh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $drawerState:Llyiahf/vczjk/li2;

.field final synthetic $navigationMenu:Ljava/lang/String;

.field final synthetic $scope:Llyiahf/vczjk/xr1;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/li2;Llyiahf/vczjk/xr1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mh2;->$navigationMenu:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/mh2;->$drawerState:Llyiahf/vczjk/li2;

    iput-object p3, p0, Llyiahf/vczjk/mh2;->$scope:Llyiahf/vczjk/xr1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/af8;

    iget-object v0, p0, Llyiahf/vczjk/mh2;->$navigationMenu:Ljava/lang/String;

    invoke-static {p1, v0}, Llyiahf/vczjk/ye8;->OooO0o0(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/mh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-object v0, v0, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    iget-object v0, v0, Llyiahf/vczjk/d9;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ni2;

    sget-object v1, Llyiahf/vczjk/ni2;->OooOOO:Llyiahf/vczjk/ni2;

    if-ne v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/lh2;

    iget-object v1, p0, Llyiahf/vczjk/mh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-object v2, p0, Llyiahf/vczjk/mh2;->$scope:Llyiahf/vczjk/xr1;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/lh2;-><init>(Llyiahf/vczjk/li2;Llyiahf/vczjk/xr1;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooOo0:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
