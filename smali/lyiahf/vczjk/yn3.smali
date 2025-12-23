.class public final Llyiahf/vczjk/yn3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $viewportHint:Llyiahf/vczjk/oja;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oja;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yn3;->$viewportHint:Llyiahf/vczjk/oja;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/wn3;

    check-cast p2, Llyiahf/vczjk/wn3;

    const-string v0, "prependHint"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "appendHint"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/yn3;->$viewportHint:Llyiahf/vczjk/oja;

    iget-object v1, p1, Llyiahf/vczjk/wn3;->OooO00o:Llyiahf/vczjk/oja;

    sget-object v2, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/yi4;->o0ooOoO(Llyiahf/vczjk/oja;Llyiahf/vczjk/oja;Llyiahf/vczjk/s25;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/yn3;->$viewportHint:Llyiahf/vczjk/oja;

    iput-object v0, p1, Llyiahf/vczjk/wn3;->OooO00o:Llyiahf/vczjk/oja;

    if-eqz v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/wn3;->OooO0O0:Llyiahf/vczjk/jl8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jl8;->OooO0oo(Ljava/lang/Object;)Z

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/yn3;->$viewportHint:Llyiahf/vczjk/oja;

    iget-object v0, p2, Llyiahf/vczjk/wn3;->OooO00o:Llyiahf/vczjk/oja;

    sget-object v1, Llyiahf/vczjk/s25;->OooOOOO:Llyiahf/vczjk/s25;

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/yi4;->o0ooOoO(Llyiahf/vczjk/oja;Llyiahf/vczjk/oja;Llyiahf/vczjk/s25;)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/yn3;->$viewportHint:Llyiahf/vczjk/oja;

    iput-object p1, p2, Llyiahf/vczjk/wn3;->OooO00o:Llyiahf/vczjk/oja;

    if-eqz p1, :cond_1

    iget-object p2, p2, Llyiahf/vczjk/wn3;->OooO0O0:Llyiahf/vczjk/jl8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/jl8;->OooO0oo(Ljava/lang/Object;)Z

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
