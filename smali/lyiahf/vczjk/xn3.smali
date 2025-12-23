.class public final Llyiahf/vczjk/xn3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $loadType:Llyiahf/vczjk/s25;

.field final synthetic $viewportHint:Llyiahf/vczjk/oja;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s25;Llyiahf/vczjk/oja;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xn3;->$loadType:Llyiahf/vczjk/s25;

    iput-object p2, p0, Llyiahf/vczjk/xn3;->$viewportHint:Llyiahf/vczjk/oja;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/wn3;

    check-cast p2, Llyiahf/vczjk/wn3;

    const-string v0, "prependHint"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "appendHint"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/xn3;->$loadType:Llyiahf/vczjk/s25;

    sget-object v1, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    if-ne v0, v1, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/xn3;->$viewportHint:Llyiahf/vczjk/oja;

    iput-object p2, p1, Llyiahf/vczjk/wn3;->OooO00o:Llyiahf/vczjk/oja;

    if-eqz p2, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/wn3;->OooO0O0:Llyiahf/vczjk/jl8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/jl8;->OooO0oo(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/xn3;->$viewportHint:Llyiahf/vczjk/oja;

    iput-object p1, p2, Llyiahf/vczjk/wn3;->OooO00o:Llyiahf/vczjk/oja;

    if-eqz p1, :cond_1

    iget-object p2, p2, Llyiahf/vczjk/wn3;->OooO0O0:Llyiahf/vczjk/jl8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/jl8;->OooO0oo(Ljava/lang/Object;)Z

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
