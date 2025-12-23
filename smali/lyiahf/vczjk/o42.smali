.class public final Llyiahf/vczjk/o42;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $this_TwoRowsTopAppBar:Llyiahf/vczjk/l1a;

.field synthetic F$0:F

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/l1a;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o42;->$this_TwoRowsTopAppBar:Llyiahf/vczjk/l1a;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    move-result p1

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance p2, Llyiahf/vczjk/o42;

    iget-object v0, p0, Llyiahf/vczjk/o42;->$this_TwoRowsTopAppBar:Llyiahf/vczjk/l1a;

    invoke-direct {p2, v0, p3}, Llyiahf/vczjk/o42;-><init>(Llyiahf/vczjk/l1a;Llyiahf/vczjk/yo1;)V

    iput p1, p2, Llyiahf/vczjk/o42;->F$0:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/o42;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/o42;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget p1, p0, Llyiahf/vczjk/o42;->F$0:F

    iget-object v1, p0, Llyiahf/vczjk/o42;->$this_TwoRowsTopAppBar:Llyiahf/vczjk/l1a;

    iget-object v1, v1, Llyiahf/vczjk/l1a;->OooOOo0:Llyiahf/vczjk/jx9;

    invoke-interface {v1}, Llyiahf/vczjk/jx9;->getState()Llyiahf/vczjk/kx9;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/o42;->$this_TwoRowsTopAppBar:Llyiahf/vczjk/l1a;

    iget-object v3, v3, Llyiahf/vczjk/l1a;->OooOOo0:Llyiahf/vczjk/jx9;

    invoke-interface {v3}, Llyiahf/vczjk/jx9;->OooO00o()Llyiahf/vczjk/t02;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/o42;->$this_TwoRowsTopAppBar:Llyiahf/vczjk/l1a;

    iget-object v4, v4, Llyiahf/vczjk/l1a;->OooOOo0:Llyiahf/vczjk/jx9;

    invoke-interface {v4}, Llyiahf/vczjk/jx9;->OooO0O0()Llyiahf/vczjk/wl;

    move-result-object v4

    iput v2, p0, Llyiahf/vczjk/o42;->label:I

    invoke-static {v1, p1, v3, v4, p0}, Llyiahf/vczjk/up;->OooO0oo(Llyiahf/vczjk/kx9;FLlyiahf/vczjk/t02;Llyiahf/vczjk/wl;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
