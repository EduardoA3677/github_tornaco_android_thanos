.class public final Llyiahf/vczjk/zk6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $isVertical:Z

.field final synthetic $scope:Llyiahf/vczjk/xr1;

.field final synthetic $state:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/lm6;Llyiahf/vczjk/xr1;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/zk6;->$isVertical:Z

    iput-object p2, p0, Llyiahf/vczjk/zk6;->$state:Llyiahf/vczjk/lm6;

    iput-object p3, p0, Llyiahf/vczjk/zk6;->$scope:Llyiahf/vczjk/xr1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/af8;

    iget-boolean v0, p0, Llyiahf/vczjk/zk6;->$isVertical:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/vk6;

    iget-object v2, p0, Llyiahf/vczjk/zk6;->$state:Llyiahf/vczjk/lm6;

    iget-object v3, p0, Llyiahf/vczjk/zk6;->$scope:Llyiahf/vczjk/xr1;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/vk6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/xr1;)V

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ie8;->OooOo:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v1, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/wk6;

    iget-object v2, p0, Llyiahf/vczjk/zk6;->$state:Llyiahf/vczjk/lm6;

    iget-object v3, p0, Llyiahf/vczjk/zk6;->$scope:Llyiahf/vczjk/xr1;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/wk6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/xr1;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOoO:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v1, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/xk6;

    iget-object v2, p0, Llyiahf/vczjk/zk6;->$state:Llyiahf/vczjk/lm6;

    iget-object v3, p0, Llyiahf/vczjk/zk6;->$scope:Llyiahf/vczjk/xr1;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/xk6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/xr1;)V

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ie8;->OooOoO0:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v1, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/yk6;

    iget-object v2, p0, Llyiahf/vczjk/zk6;->$state:Llyiahf/vczjk/lm6;

    iget-object v3, p0, Llyiahf/vczjk/zk6;->$scope:Llyiahf/vczjk/xr1;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/yk6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/xr1;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOoOO:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v1, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
