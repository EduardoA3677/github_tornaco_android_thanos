.class public final Llyiahf/vczjk/we1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $themeState$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $this_ThemeStateContainer:Landroidx/activity/ComponentActivity;

.field label:I


# direct methods
.method public constructor <init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/we1;->$this_ThemeStateContainer:Landroidx/activity/ComponentActivity;

    iput-object p2, p0, Llyiahf/vczjk/we1;->$themeState$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/we1;

    iget-object v0, p0, Llyiahf/vczjk/we1;->$this_ThemeStateContainer:Landroidx/activity/ComponentActivity;

    iget-object v1, p0, Llyiahf/vczjk/we1;->$themeState$delegate:Llyiahf/vczjk/qs5;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/we1;-><init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/we1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/we1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/we1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/we1;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/we1;->$this_ThemeStateContainer:Landroidx/activity/ComponentActivity;

    const-string v1, "<this>"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/k7a;

    const/4 v3, 0x0

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/k7a;-><init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/yo1;)V

    invoke-static {v1}, Llyiahf/vczjk/rs;->OooOO0O(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/lo0;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object p1

    const/4 v1, -0x1

    invoke-static {p1, v1}, Llyiahf/vczjk/rs;->OooOO0(Llyiahf/vczjk/f43;I)Llyiahf/vczjk/f43;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/kq9;->OooO0O0:Llyiahf/vczjk/xo8;

    invoke-virtual {v1}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/b40;

    const/4 v5, 0x4

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/b40;-><init>(Llyiahf/vczjk/gh7;I)V

    new-instance v1, Llyiahf/vczjk/oe1;

    const/4 v5, 0x3

    invoke-direct {v1, v5, v3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v5, Llyiahf/vczjk/y63;

    invoke-direct {v5, p1, v4, v1}, Llyiahf/vczjk/y63;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V

    new-instance p1, Llyiahf/vczjk/wh;

    const/4 v1, 0x4

    invoke-direct {p1, v5, v1}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    new-instance v1, Llyiahf/vczjk/pe1;

    iget-object v4, p0, Llyiahf/vczjk/we1;->$themeState$delegate:Llyiahf/vczjk/qs5;

    invoke-direct {v1, v4, v3}, Llyiahf/vczjk/pe1;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    new-instance v3, Llyiahf/vczjk/w53;

    const/4 v4, 0x1

    invoke-direct {v3, p1, v1, v4}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    new-instance p1, Llyiahf/vczjk/ve1;

    const/4 v1, 0x0

    invoke-direct {p1, v3, v1}, Llyiahf/vczjk/ve1;-><init>(Llyiahf/vczjk/w53;I)V

    invoke-static {p1}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/od;

    iget-object v3, p0, Llyiahf/vczjk/we1;->$this_ThemeStateContainer:Landroidx/activity/ComponentActivity;

    const/4 v4, 0x4

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/od;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/we1;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
