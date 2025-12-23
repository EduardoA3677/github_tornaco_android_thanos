.class public final Llyiahf/vczjk/gf;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $popupLayout:Llyiahf/vczjk/zz6;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gf;->$popupLayout:Llyiahf/vczjk/zz6;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/gf;

    iget-object v1, p0, Llyiahf/vczjk/gf;->$popupLayout:Llyiahf/vczjk/zz6;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/gf;-><init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/gf;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gf;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gf;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gf;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/gf;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/gf;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/xr1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/gf;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    move-object v1, p1

    :cond_2
    :goto_0
    invoke-static {v1}, Llyiahf/vczjk/v34;->OoooOoO(Llyiahf/vczjk/xr1;)Z

    move-result p1

    if-eqz p1, :cond_6

    sget-object p1, Llyiahf/vczjk/o6;->OooOOoo:Llyiahf/vczjk/o6;

    iput-object v1, p0, Llyiahf/vczjk/gf;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/gf;->label:I

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/pp3;->OooOOo0:Llyiahf/vczjk/pp3;

    invoke-interface {v3, v4}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v3

    if-nez v3, :cond_5

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v3

    invoke-interface {v3, p0, p1}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/gf;->$popupLayout:Llyiahf/vczjk/zz6;

    iget-object v3, p1, Llyiahf/vczjk/zz6;->Oooo0o:[I

    const/4 v4, 0x0

    aget v5, v3, v4

    aget v6, v3, v2

    iget-object v7, p1, Llyiahf/vczjk/zz6;->OooOo:Landroid/view/View;

    invoke-virtual {v7, v3}, Landroid/view/View;->getLocationOnScreen([I)V

    aget v4, v3, v4

    if-ne v5, v4, :cond_4

    aget v3, v3, v2

    if-eq v6, v3, :cond_2

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/zz6;->OooOO0o()V

    goto :goto_0

    :cond_5
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :cond_6
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
